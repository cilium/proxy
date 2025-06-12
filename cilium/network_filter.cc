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
 * Config registration for the cilium downstream network filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumDownstreamNetworkConfigFactory : public NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  absl::StatusOr<Network::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.messageValidationVisitor()),
        false, context.serverFactoryContext());
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
REGISTER_FACTORY(CiliumDownstreamNetworkConfigFactory, NamedNetworkFilterConfigFactory);

/**
 * Config registration for the cilium  filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumUpstreamNetworkConfigFactory : public NamedUpstreamNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  Network::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                        UpstreamFactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.serverFactoryContext().messageValidationVisitor()),
        true, context.serverFactoryContext());
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
REGISTER_FACTORY(CiliumUpstreamNetworkConfigFactory, NamedUpstreamNetworkFilterConfigFactory);

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace CiliumL3 {

Config::Config(const ::cilium::NetworkFilter& config, bool is_upstream,
               Server::Configuration::ServerFactoryContext& context)
    : is_upstream_(is_upstream), time_source_(context.timeSource()) {
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

void Instance::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;
}

Network::FilterStatus Instance::onNewConnection() {
  // Upstream handling happens in allowConnect() below, because upstream filter onNewconnection is
  // called after the connection has already been established, and we need to enforce policy before
  // the connection is even attempted.
  if (config_->is_upstream_) {
    return Network::FilterStatus::Continue;
  }

  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(info, "cilium.network: onNewConnection (downstream)", conn);

  auto& stream_info = conn.streamInfo();
  const auto policy_fs =
      stream_info.filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
          Cilium::CiliumPolicyFilterState::key());

  if (!policy_fs) {
    ENVOY_CONN_LOG(warn, "cilium.network: Cilium policy filter state not found", conn);
    return Network::FilterStatus::StopIteration;
  }

  const auto sni = conn.requestedServerName();

  // Pass metadata from tls_inspector to the filterstate, if any & not already
  // set via upstream cluster config.
  // TODO: Figure out if this can be left out if auto_sni and auto_san_validation are configured?
  if (!sni.empty()) {
    ENVOY_CONN_LOG(trace, "cilium.network: SNI: {}", conn, sni);

    auto& filter_state = conn.streamInfo().filterState();
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

  // Leave L7 LB policy enforcement to the upstream filter
  if (policy_fs->policyUseUpstreamDestinationAddress()) {
    return Network::FilterStatus::Continue;
  }

  if (policy_fs->pod_ip_.length() > 0) {
    Network::Address::InstanceConstSharedPtr dst_address =
        stream_info.downstreamAddressProvider().localAddress();
    const Network::Address::Ip* dip = dst_address->ip();

    // Resolve destination security ID
    uint32_t destination_identity =
        policy_fs->ingress_ ? policy_fs->source_identity_ : policy_fs->resolvePolicyId(dip);
    uint16_t destination_port = policy_fs->port_;

    if (!policy_fs->enforcePodNetworkPolicy(conn, destination_identity, destination_port, sni)) {
      log_entry_.initFromConnection(policy_fs->pod_ip_, policy_fs->proxy_id_, policy_fs->ingress_,
                                    policy_fs->source_identity_,
                                    stream_info.downstreamAddressProvider().remoteAddress(),
                                    destination_identity, dst_address, &config_->time_source_);
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      return Network::FilterStatus::StopIteration;
    }

    // TODO: access log allow for an SNI policy without HTTP rules?
  }
  return Network::FilterStatus::Continue;
}

// allowConnect is only called for upstream connections and is only configured for l7 lb
bool Instance::allowConnect(Network::Connection& conn,
                            const Network::Address::InstanceConstSharedPtr& dst_address,
                            StreamInfo::StreamInfo& stream_info) {
  // Skip enforcement and access logging on shadows
  if (stream_info.isShadow()) {
    return true;
  }

  ENVOY_CONN_LOG(info, "cilium.network: allowConnect", conn);
  RELEASE_ASSERT(config_->is_upstream_,
                 "cilium.network::allowConnect: called for downstream filter");

  const Network::Address::Ip* dip = dst_address->ip();
  if (!dip) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect: Non-IP destination address", conn);
    return false;
  }

  const auto dest_fs =
      stream_info.filterState()->getDataMutable<Cilium::CiliumDestinationFilterState>(
          Cilium::CiliumDestinationFilterState::key());
  if (!dest_fs) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect: Cilium destination filter state not found",
                   conn);
    return false;
  }

  // Set the destination address in the filter state, so that we can use it later when
  // the socket option is set for local address
  ENVOY_CONN_LOG(debug, "cilium.network::allowConnect: destination address: {}", conn,
                 dst_address->asString());
  dest_fs->setDestinationAddress(dst_address);

  const auto policy_fs =
      stream_info.filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
          Cilium::CiliumPolicyFilterState::key());
  if (!policy_fs) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect Cilium policy filter state not found", conn);
    return false;
  }

  if (!policy_fs->policyUseUpstreamDestinationAddress()) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect configured for non L7 LB", conn);
    return false;
  }

  if (policy_fs->ingress_) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect configured for ingress traffic direction",
                   conn);
    return false;
  }

  if (policy_fs->pod_ip_.length() == 0 && policy_fs->ingress_policy_name_.length() == 0) {
    ENVOY_CONN_LOG(warn, "cilium.network::allowConnect no policy configured", conn);
    return false;
  }

  // upstream connection sni can be different from the downstream connection due to HTTP routing
  const auto sni = conn.requestedServerName();

  // Resolve destination security ID
  uint32_t destination_identity = policy_fs->resolvePolicyId(dip);
  uint16_t destination_port = dip->port();

  // Check it we already have a policy verdict for this destination and port?
  auto target = std::make_pair(destination_identity, destination_port);
  auto const it = policy_cache_.find(target);
  if (it != policy_cache_.cend()) {
    // access logging needed only once per connection
    return it->second;
  }

  // Is there a pod egress policy?
  if (policy_fs->pod_ip_.length() > 0) {
    if (!policy_fs->enforcePodNetworkPolicy(conn, destination_identity, destination_port, sni)) {
      log_entry_.initFromConnection(policy_fs->pod_ip_, policy_fs->proxy_id_, false,
                                    policy_fs->source_identity_,
                                    stream_info.downstreamAddressProvider().remoteAddress(),
                                    destination_identity, dst_address, &config_->time_source_);
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      // cache the result
      policy_cache_.emplace_hint(it, target, false);
      return false;
    }
    // TODO: access log allow for an SNI policy without HTTP rules?
  }

  // Is there an Ingress policy?
  if (policy_fs->ingress_policy_name_.length() > 0) {
    log_entry_.initFromConnection(policy_fs->ingress_policy_name_, policy_fs->proxy_id_, false,
                                  policy_fs->source_identity_,
                                  stream_info.downstreamAddressProvider().remoteAddress(),
                                  destination_identity, dst_address, &config_->time_source_);

    if (!policy_fs->enforceIngressNetworkPolicy(conn, destination_identity, destination_port,
                                                sni)) {
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      // cache the result
      policy_cache_.emplace_hint(it, target, false);
      return false;
    }
    config_->log(log_entry_, ::cilium::EntryType::Request);
  }

  // cache the result
  policy_cache_.emplace_hint(it, target, true);
  return true;
}

Network::FilterStatus Instance::onData(Buffer::Instance&, bool) {
  return Network::FilterStatus::Continue;
}

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
