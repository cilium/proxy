#include "cilium/network_filter.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/stream_info/stream_info.h"
#include "envoy/upstream/host_description.h"

#include "source/common/common/logger.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_subject_alt_names.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/status/statusor.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/network_filter.pb.h"
#include "cilium/api/network_filter.pb.validate.h" // IWYU pragma: keep
#include "cilium/filter_state_cilium_destination.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/proxylib.h"
#include "proxylib/types.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumNetworkConfigFactory : public NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  absl::StatusOr<Network::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addReadFilter(std::make_shared<Filter::CiliumL3::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::NetworkFilter>();
  }

  std::string name() const override { return "cilium.network"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumNetworkConfigFactory, NamedNetworkFilterConfigFactory);

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace CiliumL3 {

Config::Config(const ::cilium::NetworkFilter& config,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.serverFactoryContext().timeSource()), access_log_(nullptr) {
  const auto& access_log_path = config.access_log_path();
  if (access_log_path.length()) {
    access_log_ = Cilium::AccessLog::open(access_log_path, time_source_);
  }
}

void Config::log(Cilium::AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->log(entry, type);
  }
}

Network::FilterStatus Instance::onNewConnection() {
  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(info, "cilium.network: onNewConnection", conn);

  const auto policy_fs =
      conn.streamInfo().filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
          Cilium::CiliumPolicyFilterState::key());

  if (!policy_fs) {
    ENVOY_CONN_LOG(warn, "cilium.network: Cilium policy filter state not found", conn);
    return Network::FilterStatus::StopIteration;
  }

  // Default to incoming destination port, may be changed for L7 LB
  destination_port_ = policy_fs->port_;

  const auto dest_fs =
      conn.streamInfo().filterState()->getDataMutable<Cilium::CiliumDestinationFilterState>(
          Cilium::CiliumDestinationFilterState::key());

  if (!dest_fs) {
    ENVOY_CONN_LOG(warn, "cilium.network: Cilium destination filter state not found", conn);
    return Network::FilterStatus::StopIteration;
  }

  // Pass SNI before the upstream callback so that it is available when upstream connection is
  // initialized.
  const auto sni = conn.requestedServerName();
  if (!sni.empty()) {
    ENVOY_CONN_LOG(trace, "cilium.network: SNI: {}", conn, sni);
  }

  // Pass metadata from tls_inspector to the filterstate, if any & not already
  // set via upstream cluster config.
  if (!sni.empty()) {
    auto filter_state = conn.streamInfo().filterState();
    auto have_sni =
        filter_state->hasData<Network::UpstreamServerName>(Network::UpstreamServerName::key());
    auto have_san = filter_state->hasData<Network::UpstreamSubjectAltNames>(
        Network::UpstreamSubjectAltNames::key());
    if (!have_sni && !have_san) {
      filter_state->setData(Network::UpstreamServerName::key(),
                            std::make_unique<Network::UpstreamServerName>(sni),
                            StreamInfo::FilterState::StateType::Mutable);
      filter_state->setData(Network::UpstreamSubjectAltNames::key(),
                            std::make_unique<Network::UpstreamSubjectAltNames>(
                                std::vector<std::string>{std::string(sni)}),
                            StreamInfo::FilterState::StateType::Mutable);
    }
  }

  callbacks_->addUpstreamCallback(
      [this, policy_fs, dest_fs, sni](Upstream::HostDescriptionConstSharedPtr host,
                                      StreamInfo::StreamInfo& stream_info) -> bool {
        // Skip enforcement or logging on shadows
        if (stream_info.isShadow()) {
          return true;
        }

        auto& conn = callbacks_->connection();
        ENVOY_CONN_LOG(info, "cilium.network: in upstream callback", conn);

        // Resolve the destination security ID and port
        uint32_t destination_identity = 0;

        Network::Address::InstanceConstSharedPtr dst_address =
            policy_fs->policyUseUpstreamDestinationAddress()
                ? host->address()
                : stream_info.downstreamAddressProvider().localAddress();
        if (nullptr == dst_address) {
          ENVOY_CONN_LOG(warn, "cilium.network (egress): No destination address", conn);
          return false;
        }

        const auto dip = dst_address->ip();
        if (!dip) {
          ENVOY_CONN_LOG(warn, "cilium.network: Non-IP destination address: {}", conn,
                         dst_address->asString());
          return false;
        }

        // Set the destination address in the filter state, so that we can use it later when
        // the socket option is set for local address
        ENVOY_CONN_LOG(debug, "cilium.network (egress): destination address: {}", conn,
                       dst_address->asString());
        dest_fs->setDestinationAddress(dst_address);

        if (policy_fs->ingress_) {
          remote_id_ = policy_fs->source_identity_;
        } else {
          remote_id_ = destination_identity;
          destination_port_ = dip->port();
          destination_identity = policy_fs->resolvePolicyId(dip);
        }

        // Check it we already have a policy verdict for this destination and port?
        auto target = std::make_pair(remote_id_, destination_port_);
        auto const it = policy_cache_.find(target);
        if (it != policy_cache_.cend()) {
          return it->second;
        }

        log_entry_.initFromConnection(policy_fs->pod_ip_, policy_fs->proxy_id_, policy_fs->ingress_,
                                      policy_fs->source_identity_,
                                      stream_info.downstreamAddressProvider().remoteAddress(),
                                      destination_identity, dst_address, &config_->time_source_);

        bool use_proxy_lib;
        std::string l7proto;
        if (!policy_fs->enforceNetworkPolicy(conn, destination_identity, destination_port_, sni,
                                             use_proxy_lib, l7proto, log_entry_)) {
          ENVOY_CONN_LOG(debug, "cilium.network: policy DENY on id: {} port: {} sni: \"{}\"", conn,
                         remote_id_, destination_port_, sni);
          config_->log(log_entry_, ::cilium::EntryType::Denied);
          // cache the result
          policy_cache_.emplace_hint(it, target, false);
          return false;
        }
        // Emit accesslog if north/south l7 lb, as in that case the traffic is not going back to bpf
        // datapath for policy enforcement
        if (log_entry_.entry_.policy_name() != policy_fs->pod_ip_) {
          config_->log(log_entry_, ::cilium::EntryType::Request);
        }
        ENVOY_LOG(debug, "cilium.network: policy ALLOW on id: {} port: {} sni: \"{}\"", remote_id_,
                  destination_port_, sni);

        // cache the result
        policy_cache_.emplace_hint(it, target, true);
        return true;
      });

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData([[maybe_unused]] Buffer::Instance& data,
                                       [[maybe_unused]] bool end_stream) {
#if 0
  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(trace, "cilium.network: onData {} bytes, end_stream: {}", conn, data.length(),
		 end_stream);
#endif
  return Network::FilterStatus::Continue;
}

#if 0
Network::FilterStatus Instance::onWrite([[maybe_unused]] Buffer::Instance& data, [[maybe_unused]] bool end_stream) {
  return Network::FilterStatus::Continue;
}
#endif
} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
