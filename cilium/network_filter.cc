#include "cilium/network_filter.h"

#include <dlfcn.h>

#include "cilium/api/network_filter.pb.validate.h"
#include "cilium/socket_option.h"
#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "common/network/upstream_server_name.h"
#include "common/network/upstream_subject_alt_names.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

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
  Network::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config, FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(
          std::make_shared<Filter::CiliumL3::Instance>(config));
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
static Registry::RegisterFactory<CiliumNetworkConfigFactory,
                                 NamedNetworkFilterConfigFactory>
    registered_;

}  // namespace Configuration
}  // namespace Server

namespace Filter {
namespace CiliumL3 {

Config::Config(const ::cilium::NetworkFilter& config,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.timeSource()), access_log_(nullptr) {
  const auto& access_log_path = config.access_log_path();
  if (access_log_path.length()) {
    access_log_ = Cilium::AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}",
                access_log_path);
    }
  }
  if (config.proxylib().length() > 0) {
    proxylib_ = std::make_shared<Cilium::GoFilter>(config.proxylib(),
                                                   config.proxylib_params());
  }
  if (config.policy_name() != "" || config.l7_proto() != "") {
    throw EnvoyException(fmt::format(
        "network: 'policy_name' and 'go_proto' are no longer supported: \'{}\'",
        config.DebugString()));
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
  ENVOY_LOG(debug, "Cilium Network: onNewConnection");
  auto& conn = callbacks_->connection();

  const auto option = Cilium::GetSocketOption(conn.socketOptions());
  if (option) {
    // Pass metadata from tls_inspector to the filterstate, if any, but not in a sidecar
    if (!option->no_mark_) {
      auto have_sni = conn.streamInfo().filterState()->hasData<Network::UpstreamServerName>(Network::UpstreamServerName::key());
      auto have_san = conn.streamInfo().filterState()->hasData<Network::UpstreamSubjectAltNames>(Network::UpstreamSubjectAltNames::key());
      if (!have_sni || !have_san) {
        const auto sni = conn.requestedServerName();
        if (sni != "") {
          conn.streamInfo().filterState()->setData(Network::UpstreamServerName::key(),
                                                   std::make_unique<Network::UpstreamServerName>(sni),
                                                   StreamInfo::FilterState::StateType::Mutable);
          conn.streamInfo().filterState()->setData(Network::UpstreamSubjectAltNames::key(),
                                                   std::make_unique<Network::UpstreamSubjectAltNames>(std::vector<std::string>{std::string(sni)}),
                                                   StreamInfo::FilterState::StateType::Mutable);
        }
      }
    }

    const std::string& policy_name = option->pod_ip_;
    if (option->policy_) {
      port_policy_ = option->policy_->findPortPolicy(
          option->ingress_, option->port_,
          option->ingress_ ? option->identity_ : option->destination_identity_);
      // populate l7proto_ if available
      if (port_policy_ != nullptr && port_policy_->useProxylib(l7proto_)) {
        if (config_->proxylib_.get() != nullptr) {
          go_parser_ = config_->proxylib_->NewInstance(
              conn, l7proto_, option->ingress_, option->identity_,
              option->destination_identity_, conn.streamInfo().downstreamAddressProvider().remoteAddress()->asString(),
              conn.streamInfo().downstreamAddressProvider().localAddress()->asString(), policy_name);
          if (go_parser_.get() == nullptr) {
            ENVOY_CONN_LOG(warn, "Cilium Network: Go parser \"{}\" not found",
                           conn, l7proto_);
            return Network::FilterStatus::StopIteration;
          }
        } else {
          log_entry_.InitFromConnection(policy_name, *option, conn.streamInfo());
        }
      }
    }
  } else {
    ENVOY_CONN_LOG(warn, "Cilium Network: Cilium Socket Option not found",
                   conn);
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data,
                                       bool end_stream) {
  auto& conn = callbacks_->connection();
  if (go_parser_) {
    FilterResult res = go_parser_->OnIO(
        false, data, end_stream);  // 'false' marks original direction data
    ENVOY_CONN_LOG(trace,
                   "Cilium Network::onData: \'GoFilter::OnIO\' returned {}",
                   conn, res);

    if (res != FILTER_OK) {
      // Drop the connection due to an error
      go_parser_->Close();
      conn.close(Network::ConnectionCloseType::NoFlush);
      return Network::FilterStatus::StopIteration;
    }

    if (go_parser_->WantReplyInject()) {
      ENVOY_CONN_LOG(
          trace, "Cilium Network::onData: calling write() on an empty buffer",
          conn);

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
    bool changed = log_entry_.UpdateFromMetadata(
        l7proto_, metadata.filter_metadata().at(l7proto_),
        config_->time_source_);

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

Network::FilterStatus Instance::onWrite(Buffer::Instance& data,
                                        bool end_stream) {
  if (go_parser_) {
    FilterResult res = go_parser_->OnIO(
        true, data, end_stream);  // 'true' marks reverse direction data
    ENVOY_CONN_LOG(trace,
                   "Cilium Network::OnWrite: \'GoFilter::OnIO\' returned {}",
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

}  // namespace CiliumL3
}  // namespace Filter
}  // namespace Envoy
