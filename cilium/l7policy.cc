#include "cilium/l7policy.h"
#include "cilium/api/l7policy.pb.validate.h"

#include <string>

#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/enum_to_int.h"
#include "common/config/utility.h"
#include "common/http/header_map_impl.h"

#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {

class ConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb
  createFilterFactory(const Json::Object& json, const std::string &,
                      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(json, context);
    return [config](
               Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  Http::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config), context);
    return [config](
               Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::L7Policy>();
  }

  std::string name() override { return "cilium.l7policy"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

Config::Config(const std::string& policy_name, const std::string& access_log_path,
	       const std::string& denied_403_body, const absl::optional<bool>& is_ingress,
	       Server::Configuration::FactoryContext& context)
    : stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(context.scope(), "cilium"))},
      policy_name_(policy_name), denied_403_body_(denied_403_body), is_ingress_(is_ingress),
      access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}", access_log_path);
    }
  }
  if (denied_403_body_.length() == 0) {
    denied_403_body_ = "Access denied";
  }
  size_t len = denied_403_body_.length();
  if (len < 2 || denied_403_body_[len-2] != '\r' || denied_403_body_[len-1] != '\n') {
    denied_403_body_.append("\r\n");
  }
}

Config::Config(const Json::Object &config, Server::Configuration::FactoryContext& context)
    : Config(config.getString("policy_name"), config.getString("access_log_path"), config.getString("denied_403_body"),
	     config.hasObject("is_ingress") ? config.getBoolean("is_ingress") : absl::optional<bool>{},
	     context) {}

Config::Config(const ::cilium::L7Policy &config, Server::Configuration::FactoryContext& context)
    : Config(config.policy_name(), config.access_log_path(), config.denied_403_body(),
	     PROTOBUF_GET_WRAPPED_OR_DEFAULT(config, is_ingress, absl::optional<bool>{}),
	     context) {}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(AccessLog::Entry &entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::HeaderMap& headers, bool) {
  headers.remove(Http::Headers::get().EnvoyOriginalDstHost);
  const auto& conn = callbacks_->connection();
  bool ingress = false;
  bool allowed = false;
  if (conn) {
    const auto option = Cilium::GetSocketOption(conn->socketOptions());
    if (option) {
      if (config_->is_ingress_) {
	ingress = config_->is_ingress_.value();
      } else {
	ingress = option->ingress_;
      }
      const std::string& policy_name = config_->policy_name_.length() ? config_->policy_name_ : option->pod_ip_;

      if (ingress) {
	allowed = option->npmap_->Allowed(policy_name, ingress, option->port_,
					  option->identity_, headers);
      } else {
	allowed = option->npmap_->Allowed(policy_name, ingress, option->port_,
					  option->destination_identity_, headers);
      }
      ENVOY_LOG(debug, "Cilium L7: {} ({}->{}) policy lookup for endpoint {}: {}",
		ingress ? "Ingress" : "Egress",
		option->identity_, option->destination_identity_,
		policy_name, allowed ? "ALLOW" : "DENY");
    } else {
      ENVOY_LOG(warn, "Cilium L7: Cilium Socket Option not found");
    }
  } else {
    ENVOY_LOG(warn, "Cilium L7: No connection");
  }

  // Fill in the log entry
  log_entry_.InitFromRequest(config_->policy_name_, ingress, callbacks_->connection(),
                             headers, callbacks_->streamInfo());
  if (!allowed) {
    denied_ = true;
    config_->stats_.access_denied_.inc();

    // Return a 403 response
    callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_, nullptr, absl::nullopt);
    return Http::FilterHeadersStatus::StopIteration;
  }

  config_->Log(log_entry_, ::cilium::EntryType::Request);
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::HeaderMap &headers,
                                                      bool) {
  log_entry_.UpdateFromResponse(headers, callbacks_->streamInfo());
  config_->Log(log_entry_, denied_ ? ::cilium::EntryType::Denied
                                   : ::cilium::EntryType::Response);
  return Http::FilterHeadersStatus::Continue;
}

} // namespace Cilium
} // namespace Envoy
