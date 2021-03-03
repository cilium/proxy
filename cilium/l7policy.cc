#include "cilium/l7policy.h"

#include <string>

#include "cilium/api/l7policy.pb.validate.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option.h"
#include "common/buffer/buffer_impl.h"
#include "common/common/enum_to_int.h"
#include "common/config/utility.h"
#include "common/network/upstream_server_name.h"
#include "common/network/upstream_subject_alt_names.h"
#include "common/http/header_map_impl.h"
#include "common/http/utility.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

namespace Envoy {
namespace Cilium {

class ConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
 public:
  Http::FilterFactoryCb createFilterFactoryFromProto(
      const Protobuf::Message& proto_config, const std::string&,
      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](
               Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::L7Policy>();
  }

  std::string name() const override { return "cilium.l7policy"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

Config::Config(const std::string& access_log_path,
               const std::string& denied_403_body,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.timeSource()),
      stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(context.scope(), "cilium"))},
      denied_403_body_(denied_403_body),
      access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}",
                access_log_path);
    }
  }
  if (denied_403_body_.length() == 0) {
    denied_403_body_ = "Access denied";
  }
  size_t len = denied_403_body_.length();
  if (len < 2 || denied_403_body_[len - 2] != '\r' ||
      denied_403_body_[len - 1] != '\n') {
    denied_403_body_.append("\r\n");
  }
}

Config::Config(const ::cilium::L7Policy& config,
               Server::Configuration::FactoryContext& context)
    : Config(config.access_log_path(), config.denied_403_body(), context) {
  if (config.policy_name() != "") {
    throw EnvoyException(fmt::format(
        "cilium.l7policy: 'policy_name' is no longer supported: \'{}\'",
        config.DebugString()));
  }
  if (config.has_is_ingress()) {
    ENVOY_LOG(warn,
              "cilium.l7policy: 'is_ingress' config option is deprecated and "
              "is ignored: \'{}\'",
              config.DebugString());
  }
}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(
    Http::RequestHeaderMap& headers, bool) {
  headers.remove(Http::Headers::get().EnvoyOriginalDstHost);
  const auto& conn = callbacks_->connection();
  bool allowed = false;

  if (conn) {
    const auto option = Cilium::GetSocketOption(conn->socketOptions());
    if (option) {
      std::string policy_name = option->pod_ip_;
      bool ingress = option->ingress_;

      // crete SNI from host header if needed, but don't do this in a sidecar
      if (!option->no_mark_) {
        auto have_sni = callbacks_->streamInfo().filterState()->hasData<Network::UpstreamServerName>(Network::UpstreamServerName::key());
        auto have_san = callbacks_->streamInfo().filterState()->hasData<Network::UpstreamSubjectAltNames>(Network::UpstreamSubjectAltNames::key());
        if (!have_sni || !have_san) {
          const auto parsed_authority = Http::Utility::parseAuthority(headers.Host()->value().getStringView());
          if (!parsed_authority.is_ip_address_) {
            callbacks_->streamInfo().filterState()->setData(Network::UpstreamServerName::key(),
                                                           std::make_unique<Network::UpstreamServerName>(parsed_authority.host_),
                                                           StreamInfo::FilterState::StateType::Mutable);
          }
          callbacks_->streamInfo().filterState()->setData(Network::UpstreamSubjectAltNames::key(),
                                                         std::make_unique<Network::UpstreamSubjectAltNames>(std::vector<std::string>{std::string(parsed_authority.host_)}),
                                                         StreamInfo::FilterState::StateType::Mutable);
        }
      }

      // Fill in the log entry
      log_entry_.InitFromRequest(policy_name, *option,
                                 callbacks_->streamInfo(), headers);

      allowed = option->policy_ &&
                option->policy_->Allowed(
                    ingress, option->port_,
                    ingress ? option->identity_ : option->destination_identity_,
                    headers, log_entry_);
      ENVOY_LOG(debug,
                "Cilium L7: {} ({}->{}) policy lookup for endpoint {}: {}",
                ingress ? "Ingress" : "Egress", option->identity_,
                option->destination_identity_, policy_name,
                allowed ? "ALLOW" : "DENY");
    } else {
      ENVOY_LOG(warn, "Cilium L7: Cilium Socket Option not found");
    }
  } else {
    ENVOY_LOG(warn, "Cilium L7: No connection");
  }

  if (!allowed) {
    denied_ = true;
    config_->stats_.access_denied_.inc();

    // Return a 403 response
    callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_,
                               nullptr, absl::nullopt, absl::string_view());
    return Http::FilterHeadersStatus::StopIteration;
  }

  config_->Log(log_entry_, ::cilium::EntryType::Request);
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(
    Http::ResponseHeaderMap& headers, bool) {
  log_entry_.UpdateFromResponse(headers, config_->time_source_);
  config_->Log(log_entry_, denied_ ? ::cilium::EntryType::Denied
                                   : ::cilium::EntryType::Response);
  return Http::FilterHeadersStatus::Continue;
}

}  // namespace Cilium
}  // namespace Envoy
