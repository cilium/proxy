#include "cilium/l7policy.h"

#include <fmt/format.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/time.h"
#include "envoy/http/codes.h"
#include "envoy/http/filter.h"
#include "envoy/http/filter_factory.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/stream_info/filter_state.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/utility.h"
#include "source/extensions/filters/http/common/factory_base.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/l7policy.pb.h"
#include "cilium/api/l7policy.pb.validate.h" // IWYU pragma: keep
#include "cilium/filter_state_cilium_policy.h"

namespace Envoy {
namespace Cilium {

class CiliumAccessFilterFactory
    : public Extensions::HttpFilters::Common::DualFactoryBase<::cilium::L7Policy> {
public:
  CiliumAccessFilterFactory() : DualFactoryBase("cilium.l7policy") {}

private:
  absl::StatusOr<Http::FilterFactoryCb>
  createFilterFactoryFromProtoTyped(const ::cilium::L7Policy& proto_config, const std::string&,
                                    DualInfo dual_info,
                                    Server::Configuration::ServerFactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(proto_config, context.timeSource(),
                                                   dual_info.scope, dual_info.is_upstream);
    return [config](Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }
};

using UpstreamCiliumAccessFilterFactory = CiliumAccessFilterFactory;

/**
 * Static registration for this filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumAccessFilterFactory, Server::Configuration::NamedHttpFilterConfigFactory);
REGISTER_FACTORY(UpstreamCiliumAccessFilterFactory,
                 Server::Configuration::UpstreamHttpFilterConfigFactory);

Config::Config(const std::string& access_log_path, const std::string& denied_403_body,
               TimeSource& time_source, Stats::Scope& scope, bool is_upstream)
    : time_source_(time_source), stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(scope, "cilium"))},
      denied_403_body_(denied_403_body), is_upstream_(is_upstream), access_log_(nullptr) {
  if (!access_log_path.empty()) {
    access_log_ = AccessLog::open(access_log_path, time_source);
  }
  if (denied_403_body_.empty()) {
    denied_403_body_ = "Access denied";
  }
  size_t len = denied_403_body_.length();
  if (len < 2 || denied_403_body_[len - 2] != '\r' || denied_403_body_[len - 1] != '\n') {
    denied_403_body_.append("\r\n");
  }
  ENVOY_LOG(debug, "cilium.l7policy: Config created");
}

Config::Config(const ::cilium::L7Policy& config, TimeSource& time_source, Stats::Scope& scope,
               bool is_upstream)
    : Config(config.access_log_path(), config.denied_403_body(), time_source, scope, is_upstream) {}

void Config::log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

void AccessFilter::sendLocalError(absl::string_view details) {
  ENVOY_LOG(warn, details);
  callbacks_->sendLocalReply(Http::Code::InternalServerError, "", nullptr, absl::nullopt,
                             StringUtil::replaceAllEmptySpace(details));
}

void AccessFilter::setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;

  // Create log entry if not already in filter state
  log_entry_ =
      callbacks_->streamInfo().filterState()->getDataMutable<AccessLog::Entry>(AccessLogKey);
  if (log_entry_ == nullptr) {
    auto log_entry = std::make_unique<AccessLog::Entry>();
    log_entry_ = log_entry.get();
    callbacks_->streamInfo().filterState()->setData(AccessLogKey, std::move(log_entry),
                                                    StreamInfo::FilterState::StateType::Mutable,
                                                    StreamInfo::FilterState::LifeSpan::Request);
  }

  if (config_->is_upstream_) {
    callbacks_->upstreamCallbacks()->addUpstreamCallbacks(*this);
  }
}

void AccessFilter::onUpstreamConnectionEstablished() {
  if (latched_end_stream_.has_value()) {
    const bool end_stream = *latched_end_stream_;
    latched_end_stream_.reset();
    ENVOY_CONN_LOG(debug,
                   "cilium.l7policy: RESUMING after upstream connection has been established",
                   callbacks_->connection().ref());
    Http::FilterHeadersStatus status = decodeHeaders(*latched_headers_, end_stream);
    if (status == Http::FilterHeadersStatus::Continue) {
      callbacks_->continueDecoding();
    }
  }
}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::RequestHeaderMap& headers,
                                                      bool end_stream) {
  StreamInfo::StreamInfo& stream_info = callbacks_->streamInfo();

  // Skip enforcement or logging on shadows and ingress direction
  if (stream_info.isShadow()) {
    return Http::FilterHeadersStatus::Continue;
  }

  const auto& conn = callbacks_->connection();

  if (!conn) {
    sendLocalError("cilium.l7policy: No connection");
    return Http::FilterHeadersStatus::StopIteration;
  }

  if (log_entry_ == nullptr) {
    sendLocalError("cilium.l7policy: No log entry");
    return Http::FilterHeadersStatus::StopIteration;
  }

  const auto policy_fs =
      conn->streamInfo().filterState().getDataReadOnly<Cilium::CiliumPolicyFilterState>(
          Cilium::CiliumPolicyFilterState::key());

  if (!policy_fs) {
    sendLocalError("cilium.l7policy: Cilium policy filter state not found");
    return Http::FilterHeadersStatus::StopIteration;
  }

  ENVOY_CONN_LOG(debug, "cilium.l7policy: {} decodeHeaders()", conn.ref(),
                 config_->is_upstream_ ? "upstream" : "downstream");

  // Handle downstream case first
  if (!config_->is_upstream_) {
    const auto& dst_address = stream_info.downstreamAddressProvider().localAddress();
    const auto dip = dst_address->ip();
    // destination identity should be reported as 0 for an ingress policy
    uint32_t destination_identity = policy_fs->ingress_ ? 0 : policy_fs->resolvePolicyId(dip);
    uint16_t destination_port = dip->port();

    // Initialize log entry in the beginning of downstream processing
    log_entry_->initFromRequest(
        policy_fs->pod_ip_, policy_fs->proxy_id_, policy_fs->ingress_, policy_fs->source_identity_,
        callbacks_->streamInfo().downstreamAddressProvider().remoteAddress(), destination_identity,
        dst_address, stream_info, headers);

    // Enforce pod policy only for local pods without L7 LB
    if (!policy_fs->policyUseUpstreamDestinationAddress() && !policy_fs->pod_ip_.empty()) {
      bool allowed =
          policy_fs->enforcePodHTTPPolicy(conn.ref(), destination_identity, destination_port,
                                          headers, config_->pod_policy_cache_, *log_entry_);

      // Update the log entry with current headers, as the policy may have altered them.
      log_entry_->updateFromRequest(destination_identity, dst_address, headers);

      if (!allowed) {
        config_->log(*log_entry_, ::cilium::EntryType::Denied);
        callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_, nullptr,
                                   absl::nullopt, absl::string_view());
        return Http::FilterHeadersStatus::StopIteration;
      }

      // Log as a forwarded request
      config_->log(*log_entry_, ::cilium::EntryType::Request);
    }

  } else { // is_upstream_
    // Skip enforcement for non L7LB (which is always egress).
    // TODO: Drop and warn when Cilium Agent no longer mistakenly configures upstream enforcement or
    // non-L7LB
    if (!policy_fs->policyUseUpstreamDestinationAddress()) {
      ENVOY_CONN_LOG(debug, "cilium.l7policy: upstream enforcement configured for non L7 LB",
                     conn.ref());
      return Http::FilterHeadersStatus::Continue;
    }
    if (policy_fs->ingress_) {
      ENVOY_CONN_LOG(
          debug, "cilium.l7policy: upstream enforcement configured for ingress traffic direction",
          conn.ref());
      return Http::FilterHeadersStatus::Continue;
    }

    // must have a policy configured
    // This is safe as the upstream filter was introduced at Cilium 1.16 and
    // bpf_metadata config has had 'enforce_policy_on_l7lb' set since Cilium 1.15.
    if (policy_fs->pod_ip_.empty() && policy_fs->ingress_policy_name_.empty()) {
      ENVOY_CONN_LOG(warn, "cilium.network: no policy configured", conn.ref());
      return Http::FilterHeadersStatus::StopIteration;
    }

    // Pause upstream decoding until connection has been established
    ASSERT(callbacks_->upstreamCallbacks());
    if (!callbacks_->upstreamCallbacks()->upstream()) {
      latched_headers_ = headers;
      latched_end_stream_ = end_stream;
      ENVOY_CONN_LOG(debug,
                     "cilium.l7policy: PAUSING until upstream connection has been established",
                     conn.ref());
      return Http::FilterHeadersStatus::StopAllIterationAndWatermark;
    }

    const auto& dst_address = stream_info.upstreamInfo()->upstreamHost()->address();
    if (nullptr == dst_address) {
      sendLocalError("cilium.l7policy: No destination address");
      return Http::FilterHeadersStatus::StopIteration;
    }
    const auto dip = dst_address->ip();
    if (!dip) {
      sendLocalError(
          fmt::format("cilium.l7policy: Non-IP destination address: {}", dst_address->asString()));
      return Http::FilterHeadersStatus::StopIteration;
    }

    uint32_t destination_identity = policy_fs->resolvePolicyId(dip);
    uint16_t destination_port = dip->port();
    bool allowed;

    // Is there a pod egress policy?
    if (!policy_fs->pod_ip_.empty()) {
      allowed = policy_fs->enforcePodHTTPPolicy(conn.ref(), destination_identity, destination_port,
                                                headers, config_->pod_policy_cache_, *log_entry_);

      // Update the log entry with current headers, as the policy may have altered them.
      log_entry_->updateFromRequest(destination_identity, dst_address, headers);

      if (!allowed) {
        config_->log(*log_entry_, ::cilium::EntryType::Denied);
        callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_, nullptr,
                                   absl::nullopt, absl::string_view());
        return Http::FilterHeadersStatus::StopIteration;
      }
    }

    // Is there an Ingress policy?
    if (!policy_fs->ingress_policy_name_.empty()) {
      allowed =
          policy_fs->enforceIngressHTTPPolicy(conn.ref(), destination_identity, destination_port,
                                              headers, config_->ingress_policy_cache_, *log_entry_);

      // Update the log entry with current headers, as the policy may have altered them.
      log_entry_->updateFromRequest(destination_identity, dst_address, headers);

      if (!allowed) {
        config_->log(*log_entry_, ::cilium::EntryType::Denied);
        callbacks_->sendLocalReply(Http::Code::Forbidden, config_->denied_403_body_, nullptr,
                                   absl::nullopt, absl::string_view());
        return Http::FilterHeadersStatus::StopIteration;
      }
    }
    // Log as a forwarded request
    config_->log(*log_entry_, ::cilium::EntryType::Request);
  }
  return Http::FilterHeadersStatus::Continue;
}

void AccessFilter::onStreamComplete() {
  // Request may have been left unlogged due to an error and/or missing local reply
  if (log_entry_ && !log_entry_->request_logged_) {
    config_->log(*log_entry_, ::cilium::EntryType::Request);
  }
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::ResponseHeaderMap& headers, bool) {
  // Skip enforcement or logging on shadows
  if (callbacks_->streamInfo().isShadow()) {
    return Http::FilterHeadersStatus::Continue;
  }

  ENVOY_CONN_LOG(debug, "cilium.l7policy: {} encodeHeaders()", callbacks_->connection().ref(),
                 config_->is_upstream_ ? "upstream" : "downstream");

  // Nothing to do in the upstream filter
  if (config_->is_upstream_) {
    return Http::FilterHeadersStatus::Continue;
  }

  if (log_entry_ == nullptr) {
    return Http::FilterHeadersStatus::Continue;
  }

  // Request may have been left unlogged due to an error or L3/4 deny
  if (!log_entry_->request_logged_) {
    // Default logging local errors as "forwarded".
    // The response log will contain the locally generated HTTP error code.
    auto log_type = ::cilium::EntryType::Request;

    if (headers.Status()->value() == "403") {
      // Log as a denied request.
      log_type = ::cilium::EntryType::Denied;
      config_->stats_.access_denied_.inc();
    }
    config_->log(*log_entry_, log_type);
  }

  // Log the response
  log_entry_->updateFromResponse(headers, config_->time_source_);
  config_->log(*log_entry_, ::cilium::EntryType::Response);
  return Http::FilterHeadersStatus::Continue;
}

} // namespace Cilium
} // namespace Envoy
