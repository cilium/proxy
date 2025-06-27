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

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_subject_alt_names.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
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
      filter_manager.addFilter(std::make_shared<Filter::CiliumL3::Instance>(config));
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
  if (config.proxylib().length() > 0) {
    proxylib_ = std::make_shared<Cilium::GoFilter>(config.proxylib(), config.proxylib_params());
  }
}

void Config::log(Cilium::AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->log(entry, type);
  }
}

bool Instance::enforceNetworkPolicy(const Cilium::CiliumPolicyFilterState* policy_fs,
                                    Cilium::CiliumDestinationFilterState* dest_fs,
                                    uint32_t destination_identity,
                                    Network::Address::InstanceConstSharedPtr dst_address,
                                    absl::string_view sni, StreamInfo::StreamInfo& stream_info) {
  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(debug, "cilium.network: enforceNetworkPolicy", conn);

  // Set the destination address in the filter state, so that we can use it later when
  // the socket option is set for local address
  ENVOY_CONN_LOG(debug, "cilium.network: destination address: {}", conn, dst_address->asString());
  dest_fs->setDestinationAddress(dst_address);

  // Is there a pod egress policy?
  bool use_proxy_lib = false;
  if (policy_fs->pod_ip_.length() > 0) {
    if (!policy_fs->enforcePodNetworkPolicy(conn, destination_identity, destination_port_, sni,
                                            use_proxy_lib, l7proto_)) {
      log_entry_.initFromConnection(policy_fs->pod_ip_, policy_fs->proxy_id_, false,
                                    policy_fs->source_identity_,
                                    stream_info.downstreamAddressProvider().remoteAddress(),
                                    destination_identity, dst_address, &config_->time_source_);
      config_->log(log_entry_, ::cilium::EntryType::Denied);
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

    if (!policy_fs->enforceIngressNetworkPolicy(conn, destination_identity, destination_port_,
                                                sni)) {
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      return false;
    }
    config_->log(log_entry_, ::cilium::EntryType::Request);
  }

  if (use_proxy_lib) {
    const std::string& policy_name = policy_fs->pod_ip_;

    // Initialize Go parser if requested
    if (config_->proxylib_.get() != nullptr) {
      go_parser_ = config_->proxylib_->newInstance(
          conn, l7proto_, policy_fs->ingress_, policy_fs->source_identity_, destination_identity,
          stream_info.downstreamAddressProvider().remoteAddress()->asString(),
          dst_address->asString(), policy_name);
      if (go_parser_.get() == nullptr) {
        ENVOY_CONN_LOG(warn, "cilium.network: Go parser \"{}\" not found", conn, l7proto_);
        return false;
      }
    }
  }
  should_buffer_ = false;
  return true;
}

Network::FilterStatus Instance::onNewConnection() {
  // Upstream handling happens in onDestinationSelected() below.
  if (config_->is_upstream_) {
    return Network::FilterStatus::Continue;
  }

  // If there is no upstream filter, onDestinationSelected for the upstream connection
  // will be called on the downstream filter instead, but after this call.

  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(debug, "cilium.network: onNewConnection (downstream)", conn);

  // Buffer data until proxylib policy is available, if configured with proxylib
  if (config_->proxylib_.get() != nullptr) {
    should_buffer_ = true;
  }

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

  // Add DownstreamConnection filter state for compat with legacy configurations without upstream
  // filter
  stream_info.filterState()->setData(
      Network::Cilium::DownstreamConnection::key(),
      std::make_shared<Network::Cilium::DownstreamConnection>(&conn),
      StreamInfo::FilterState::StateType::ReadOnly, StreamInfo::FilterState::LifeSpan::Connection,
      StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnection);

  // Leave L7 LB policy enforcement to the upstream filter, or to the onDestinationSelected callback
  if (policy_fs->policyUseUpstreamDestinationAddress()) {
    return Network::FilterStatus::Continue;
  }

  const auto dest_fs =
      stream_info.filterState()->getDataMutable<Cilium::CiliumDestinationFilterState>(
          Cilium::CiliumDestinationFilterState::key());
  if (!dest_fs) {
    ENVOY_CONN_LOG(
        warn, "cilium.network::onDestinationSelected: Cilium destination filter state not found",
        conn);
    return Network::FilterStatus::StopIteration;
  }

  Network::Address::InstanceConstSharedPtr dst_address =
      stream_info.downstreamAddressProvider().localAddress();
  const auto dip = dst_address->ip();

  // Resolve the destination security ID and port
  uint32_t destination_identity = 0; // left as 0 for an ingress policy

  if (policy_fs->ingress_) {
    destination_port_ = policy_fs->port_;
    remote_id_ = policy_fs->source_identity_;
  } else {
    destination_port_ = dip->port();
    destination_identity = policy_fs->resolvePolicyId(dip);
    remote_id_ = destination_identity;
  }

  if (!enforceNetworkPolicy(policy_fs, dest_fs, destination_identity, dst_address, sni,
                            stream_info)) {
    stream_info.setResponseFlag(StreamInfo::CoreResponseFlag::UnauthorizedExternalService);
    conn.close(Network::ConnectionCloseType::AbortReset, "access denied");
    return Network::FilterStatus::StopIteration;
  }

  return Network::FilterStatus::Continue;
}

// onDestinationSelected is called before an upstream connection is attempted.
// Called on the downstream filter only if none of the upstream network filter implements this and
// returns a FilterStatus.
absl::optional<Network::FilterStatus>
Instance::onDestinationSelected(const Network::Address::InstanceConstSharedPtr& dst_address,
                                StreamInfo::StreamInfo& stream_info) {
  // Skip enforcement and access logging on shadows
  if (stream_info.isShadow()) {
    return Network::FilterStatus::Continue;
  }

  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(info, "cilium.network: onDestinationSelected ({})", conn,
                 config_->is_upstream_ ? "upstream" : "downstream");

  const auto policy_fs =
      stream_info.filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
          Cilium::CiliumPolicyFilterState::key());
  if (!policy_fs) {
    ENVOY_CONN_LOG(
        warn, "cilium.network::onDestinationSelected Cilium policy filter state not found", conn);
    return Network::FilterStatus::StopIteration;
  }

  const auto dest_fs =
      stream_info.filterState()->getDataMutable<Cilium::CiliumDestinationFilterState>(
          Cilium::CiliumDestinationFilterState::key());
  if (!dest_fs) {
    ENVOY_CONN_LOG(
        warn, "cilium.network::onDestinationSelected: Cilium destination filter state not found",
        conn);
    return Network::FilterStatus::StopIteration;
  }

  // Set the destination address in the filter state, so that we can use it later when
  // the socket option is set for local address
  ENVOY_CONN_LOG(debug, "cilium.network::onDestinationSelected: destination address: {}", conn,
                 dst_address->asString());
  dest_fs->setDestinationAddress(dst_address);

  // Only enforce L7 LB policy here, non-L7 LB policy has already been enforced on the downstream
  // onNewConnection callback.
  if (policy_fs->policyUseUpstreamDestinationAddress()) {
    if (policy_fs->pod_ip_.length() == 0 && policy_fs->ingress_policy_name_.length() == 0) {
      ENVOY_CONN_LOG(warn, "cilium.network::onDestinationSelected no policy configured", conn);
      return Network::FilterStatus::StopIteration;
    }

    // upstream connection sni can be different from the downstream connection due to HTTP routing
    const auto sni = conn.requestedServerName();

    // Resolve destination security ID
    const Network::Address::Ip* dip = dst_address->ip();
    uint32_t destination_identity = policy_fs->resolvePolicyId(dip);
    destination_port_ = dip->port();

    remote_id_ = destination_identity;

    if (!enforceNetworkPolicy(policy_fs, dest_fs, destination_identity, dst_address, sni,
                              stream_info)) {
      return Network::FilterStatus::StopIteration;
    }
  }
  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data, bool end_stream) {
  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(trace, "cilium.network: onData {} bytes, end_stream: {}", conn, data.length(),
                 end_stream);
  const char* reason;

  if (should_buffer_) {
    // Buffer data until upstream is selected and policy resolved
    buffer_.move(data);
    return Network::FilterStatus::Continue;
  }
  // Prepend buffered data if any
  if (buffer_.length() > 0) {
    data.prepend(buffer_);
  }
  if (go_parser_) {
    FilterResult res =
        go_parser_->onIo(false, data, end_stream); // 'false' marks original direction data
    ENVOY_CONN_LOG(trace, "cilium.network::onData: \'GoFilter::OnIO\' returned {}", conn,
                   Envoy::Cilium::toString(res));

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->close();
      reason = "proxylib error";
      goto drop_close;
    }

    if (go_parser_->wantReplyInject()) {
      ENVOY_CONN_LOG(trace, "cilium.network::onData: calling write() on an empty buffer", conn);

      // We have no idea when, if ever new data will be received on the
      // reverse direction. Connection write on an empty buffer will cause
      // write filter chain to be called, and gives our write path the
      // opportunity to inject data.
      Buffer::OwnedImpl empty;
      conn.write(empty, false);
    }

    go_parser_->setOrigEndStream(end_stream);
  } else if (!l7proto_.empty()) {
    const auto& metadata = conn.streamInfo().dynamicMetadata();
    bool changed = log_entry_.updateFromMetadata(l7proto_, metadata.filter_metadata().at(l7proto_));

    // Policy may have changed since the connection was established, get fresh policy
    const auto policy_fs =
        conn.streamInfo().filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
            Cilium::CiliumPolicyFilterState::key());

    if (!policy_fs) {
      ENVOY_CONN_LOG(warn,
                     "cilium.network: Cilium policy filter state not found for pod {}, "
                     "defaulting to DENY",
                     conn, policy_fs->pod_ip_);
      reason = "Cilium metadata lost";
      goto drop_close;
    }
    const auto& policy = policy_fs->getPolicy();
    auto port_policy = policy.findPortPolicy(policy_fs->ingress_, destination_port_);
    if (!port_policy.allowed(policy_fs->proxy_id_, remote_id_, metadata)) {
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      reason = "metadata policy drop";
      goto drop_close;
    } else {
      // accesslog only if metadata has changed
      if (changed) {
        config_->log(log_entry_, ::cilium::EntryType::Request);
      }
    }
  }

  return Network::FilterStatus::Continue;

drop_close:
  conn.close(Network::ConnectionCloseType::NoFlush, reason);
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Instance::onWrite(Buffer::Instance& data, bool end_stream) {
  if (go_parser_) {
    FilterResult res =
        go_parser_->onIo(true, data, end_stream); // 'true' marks reverse direction data
    ENVOY_CONN_LOG(trace, "cilium.network::OnWrite: \'GoFilter::OnIO\' returned {}",
                   callbacks_->connection(), Envoy::Cilium::toString(res));

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->close();
      return Network::FilterStatus::StopIteration;
    }

    // XXX: Unfortunately continueReading() continues from the next filter, and
    // there seems to be no way to trigger the whole filter chain to be called.

    go_parser_->setReplyEndStream(end_stream);
  }

  return Network::FilterStatus::Continue;
}

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
