#include "cilium/l7policy.h"

#include <string>

#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/config/utility.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/utility.h"
#include "source/common/network/upstream_server_name.h"
#include "source/common/network/upstream_subject_alt_names.h"

#include "cilium/api/l7policy.pb.validate.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {

class ConfigFactory : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
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
REGISTER_FACTORY(ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory);

Config::Config(const std::string& access_log_path, const std::string& denied_403_body,
               Server::Configuration::FactoryContext& context)
    : time_source_(context.timeSource()), stats_{ALL_CILIUM_STATS(
                                              POOL_COUNTER_PREFIX(context.scope(), "cilium"))},
      denied_403_body_(denied_403_body), access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path);
  }
  if (denied_403_body_.length() == 0) {
    denied_403_body_ = "Access denied";
  }
  size_t len = denied_403_body_.length();
  if (len < 2 || denied_403_body_[len - 2] != '\r' || denied_403_body_[len - 1] != '\n') {
    denied_403_body_.append("\r\n");
  }
}

Config::Config(const ::cilium::L7Policy& config, Server::Configuration::FactoryContext& context)
    : Config(config.access_log_path(), config.denied_403_body(), context) {}

void Config::Log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::RequestHeaderMap& headers, bool) {
  const auto& conn = callbacks_->connection();

  if (!conn) {
    ENVOY_LOG(warn, "cilium.l7policy: No connection");
    // Return a 500 response
    callbacks_->sendLocalReply(Http::Code::InternalServerError, "", nullptr, absl::nullopt,
                               absl::string_view());
    return Http::FilterHeadersStatus::StopIteration;
  }

  const Network::Socket::OptionsSharedPtr socketOptions = conn->socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (!option) {
    ENVOY_LOG(warn, "cilium.l7policy: Cilium Socket Option not found");
    // Return a 500 response
    callbacks_->sendLocalReply(Http::Code::InternalServerError, "", nullptr, absl::nullopt,
                               absl::string_view());
    return Http::FilterHeadersStatus::StopIteration;
  }

  // Initialize the log entry
  log_entry_.InitFromRequest(option->pod_ip_, option->proxy_id_, option->ingress_,
                             option->identity_,
                             callbacks_->streamInfo().downstreamAddressProvider().remoteAddress(),
                             0, callbacks_->streamInfo().downstreamAddressProvider().localAddress(),
                             callbacks_->streamInfo(), headers);

  // This callback is never called if upstream connection fails
  callbacks_->addUpstreamCallback([this, option](Http::RequestHeaderMap& headers,
                                                 StreamInfo::StreamInfo& stream_info) -> bool {
    // Destination may have changed due to upstream routing and load balancing.
    // Use original destination address for policy enforcement when not L7 LB, even if the actual
    // destination may have chanegd. This can happen with custom Envoy Listeners.
    const Network::Address::InstanceConstSharedPtr& dst_address =
        option->policyUseUpstreamDestinationAddress()
            ? stream_info.upstreamInfo()->upstreamHost()->address()
            : callbacks_->streamInfo().downstreamAddressProvider().localAddress();

    if (nullptr == dst_address) {
      ENVOY_LOG(warn, "cilium.l7policy: No destination address");
      return false;
    }
    const auto dip = dst_address->ip();
    if (!dip) {
      ENVOY_LOG_MISC(warn, "cilium.l7policy: Non-IP destination address: {}",
                     dst_address->asString());
      return false;
    }
    uint32_t destination_port = dip->port();
    uint32_t destination_identity = option->resolvePolicyId(dip);

    // Policy may have changed since the connection was established, get fresh policy
    const auto& policy = option->getPolicy();
    if (!policy) {
      ENVOY_LOG(debug, "cilium.l7policy: No policy found for pod {}, defaulting to DENY",
                option->pod_ip_);
      return false;
    }

    allowed_ = true;
    if (option->ingress_source_identity_ != 0) {
      allowed_ = policy->Allowed(true, option->port_, option->ingress_source_identity_, headers,
                                 log_entry_);
      ENVOY_LOG(debug,
                "cilium.l7policy: Ingress from {} policy lookup for endpoint {} for port {}: {}",
                option->ingress_source_identity_, option->pod_ip_, option->port_,
                allowed_ ? "ALLOW" : "DENY");
    }
    if (allowed_) {
      allowed_ = policy->Allowed(option->ingress_, destination_port,
                                 option->ingress_ ? option->identity_ : destination_identity,
                                 headers, log_entry_);
      ENVOY_LOG(debug, "cilium.l7policy: {} ({}->{}) policy lookup for endpoint {} for port {}: {}",
                option->ingress_ ? "ingress" : "egress", option->identity_, destination_identity,
                option->pod_ip_, destination_port, allowed_ ? "ALLOW" : "DENY");
    }
    // Update the log entry with the chosen destination address and current headers, as remaining
    // filters, upstream, and/or policy may have altered headers.
    log_entry_.UpdateFromRequest(destination_identity, dst_address, headers);

    if (allowed_) {
      // Log as a forwarded request
      config_->Log(log_entry_, ::cilium::EntryType::Request);
    }

    return allowed_;
  });

  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  // Accepted & forwaded requests are logged by the upstream callback. Requests can remain unlogged
  // if they are not accepted or any other error happens and upstream callback is never called.
  // Logging the (locally generated) response is not enough as we no longer log request headers with
  // responses.
  if (!allowed_) {
    // Request was not yet logged. Log it so that the headers get logged.
    // Default logging local errors as "forwarded".
    // The response log will contain the locally generated HTTP error code.
    auto logType = ::cilium::EntryType::Request;

    if (headers.Status()->value() == "403") {
      // Log as a denied request.
      logType = ::cilium::EntryType::Denied;
      config_->stats_.access_denied_.inc();
    }
    config_->Log(log_entry_, logType);
  }

  // Log the response
  log_entry_.UpdateFromResponse(headers, config_->time_source_);
  config_->Log(log_entry_, ::cilium::EntryType::Response);

  return Http::FilterHeadersStatus::Continue;
}

} // namespace Cilium
} // namespace Envoy
