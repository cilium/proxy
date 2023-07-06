#include "cilium/network_filter.h"

#include <dlfcn.h>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/common/common/assert.h"
#include "source/common/common/fmt.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_subject_alt_names.h"

#include "cilium/api/network_filter.pb.validate.h"
#include "cilium/socket_option.h"

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
  Network::FilterFactoryCb createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                                                        FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.messageValidationVisitor()),
        context);
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
REGISTER_FACTORY(CiliumNetworkConfigFactory, NamedNetworkFilterConfigFactory);

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace CiliumL3 {

Config::Config(const ::cilium::NetworkFilter& config,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.timeSource()), access_log_(nullptr) {
  const auto& access_log_path = config.access_log_path();
  if (access_log_path.length()) {
    access_log_ = Cilium::AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}", access_log_path);
    }
  }
  if (config.proxylib().length() > 0) {
    proxylib_ = std::make_shared<Cilium::GoFilter>(config.proxylib(), config.proxylib_params());
  }
}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(Cilium::AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(debug, "cilium.network: onNewConnection");

  // Buffer data until proxylib policy is available, if configured with proxylib
  if (config_->proxylib_.get() != nullptr) {
    should_buffer_ = true;
  }

  auto& conn = callbacks_->connection();
  const Network::Socket::OptionsSharedPtr socketOptions = conn.socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);

  if (!option) {
    ENVOY_CONN_LOG(warn, "cilium.network: Cilium Socket Option not found", conn);
    return Network::FilterStatus::StopIteration;
  }

  // Pass SNI before the upstream callback so that it is available when upstream connection is
  // initialized.
  const auto sni = conn.requestedServerName();
  if (sni != "") {
    ENVOY_CONN_LOG(trace, "cilium.network: SNI: {}", conn, sni);
  }

  // Pass metadata from tls_inspector to the filterstate, if any & not already
  // set via upstream cluster config, but not in a sidecar, which have no mark
  if (sni != "" && option->mark_ != 0) {
    auto filterState = conn.streamInfo().filterState();
    auto have_sni =
        filterState->hasData<Network::UpstreamServerName>(Network::UpstreamServerName::key());
    auto have_san = filterState->hasData<Network::UpstreamSubjectAltNames>(
        Network::UpstreamSubjectAltNames::key());
    if (!have_sni && !have_san) {
      filterState->setData(Network::UpstreamServerName::key(),
                           std::make_unique<Network::UpstreamServerName>(sni),
                           StreamInfo::FilterState::StateType::Mutable);
      filterState->setData(Network::UpstreamSubjectAltNames::key(),
                           std::make_unique<Network::UpstreamSubjectAltNames>(
                               std::vector<std::string>{std::string(sni)}),
                           StreamInfo::FilterState::StateType::Mutable);
    }
  }

  callbacks_->addUpstreamCallback([this, option, sni](Upstream::HostDescriptionConstSharedPtr host,
                                                      StreamInfo::StreamInfo& stream_info) -> bool {
    ENVOY_LOG(trace, "cilium.network: in upstream callback");
    auto& conn = callbacks_->connection();

    // Resolve the destination security ID and port
    uint32_t destination_identity = 0;
    uint32_t destination_port = option->port_;

    Network::Address::InstanceConstSharedPtr dst_address =
        option->policyUseUpstreamDestinationAddress()
            ? host->address()
            : stream_info.downstreamAddressProvider().localAddress();
    if (nullptr == dst_address) {
      ENVOY_LOG(warn, "cilium.network (egress): No destination address ");
      return false;
    }
    if (!option->ingress_) {
      const auto dip = dst_address->ip();
      if (!dip) {
        ENVOY_LOG_MISC(warn, "cilium.network: Non-IP destination address: {}",
                       dst_address->asString());
        return false;
      }
      destination_port = dip->port();
      destination_identity = option->resolvePolicyId(dip);
    }

    port_policy_ = option->initial_policy_->findPortPolicy(option->ingress_, destination_port,
                                                           option->ingress_ ? option->identity_
                                                                            : destination_identity);
    if (port_policy_ == nullptr) {
      ENVOY_CONN_LOG(warn, "cilium.network: Policy NOT FOUND for id: {} port: {}", conn,
                     option->ingress_ ? option->identity_ : destination_identity, destination_port);
      return false;
    }

    if (!port_policy_->Matches(sni, option->ingress_ ? option->identity_ : destination_identity)) {
      // Connection not allowed by policy
      ENVOY_CONN_LOG(warn, "cilium.network: Policy DENY on id: {} port: {}", conn,
                     option->ingress_ ? option->identity_ : destination_identity, destination_port);
      return false;
    }

    const std::string& policy_name = option->pod_ip_;
    // populate l7proto_ if available
    if (port_policy_->useProxylib(l7proto_)) {
      // Initialize Go parser if requested
      if (config_->proxylib_.get() != nullptr) {
        go_parser_ = config_->proxylib_->NewInstance(
            conn, l7proto_, option->ingress_, option->identity_, destination_identity,
            stream_info.downstreamAddressProvider().remoteAddress()->asString(),
            dst_address->asString(), policy_name);
        if (go_parser_.get() == nullptr) {
          ENVOY_CONN_LOG(warn, "cilium.network: Go parser \"{}\" not found", conn, l7proto_);
          return false;
        }
      } else { // no Go parser, initialize logging for metadata based access control
        log_entry_.InitFromConnection(policy_name, option->proxy_id_, option->ingress_,
                        	      option->identity_,
                                      stream_info.downstreamAddressProvider().remoteAddress(),
                                      destination_identity, dst_address, &config_->time_source_);
      }
    }
    should_buffer_ = false;
    return true;
  });

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "cilium.network: onData {} bytes, end_stream: {}", data.length(), end_stream);

  if (should_buffer_) {
    // Buffer data until upstream is selected and policy resolved
    buffer_.move(data);
    return Network::FilterStatus::Continue;
  }
  // Prepend buffered data if any
  if (buffer_.length() > 0) {
    data.prepend(buffer_);
  }
  auto& conn = callbacks_->connection();
  if (go_parser_) {
    FilterResult res =
        go_parser_->OnIO(false, data, end_stream); // 'false' marks original direction data
    ENVOY_CONN_LOG(trace, "cilium.network::onData: \'GoFilter::OnIO\' returned {}", conn, res);

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->Close();
      conn.close(Network::ConnectionCloseType::NoFlush);
      return Network::FilterStatus::StopIteration;
    }

    if (go_parser_->WantReplyInject()) {
      ENVOY_CONN_LOG(trace, "cilium.network::onData: calling write() on an empty buffer", conn);

      // We have no idea when, if ever new data will be received on the
      // reverse direction. Connection write on an empty buffer will cause
      // write filter chain to be called, and gives our write path the
      // opportunity to inject data.
      Buffer::OwnedImpl empty;
      conn.write(empty, false);
    }

    go_parser_->SetOrigEndStream(end_stream);
  } else if (port_policy_ != nullptr && !l7proto_.empty()) {
    const auto& metadata = conn.streamInfo().dynamicMetadata();
    bool changed = log_entry_.UpdateFromMetadata(l7proto_, metadata.filter_metadata().at(l7proto_));

    if (!port_policy_->allowed(metadata)) {
      conn.close(Network::ConnectionCloseType::NoFlush);
      config_->Log(log_entry_, ::cilium::EntryType::Denied);
      return Network::FilterStatus::StopIteration;
    } else {
      // accesslog only if metadata has changed
      if (changed) {
        config_->Log(log_entry_, ::cilium::EntryType::Request);
      }
    }
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onWrite(Buffer::Instance& data, bool end_stream) {
  if (go_parser_) {
    FilterResult res =
        go_parser_->OnIO(true, data, end_stream); // 'true' marks reverse direction data
    ENVOY_CONN_LOG(trace, "cilium.network::OnWrite: \'GoFilter::OnIO\' returned {}",
                   callbacks_->connection(), res);

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->Close();
      return Network::FilterStatus::StopIteration;
    }

    // XXX: Unfortunately continueReading() continues from the next filter, and
    // there seems to be no way to trigger the whole filter chain to be called.

    go_parser_->SetReplyEndStream(end_stream);
  }

  return Network::FilterStatus::Continue;
}

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
