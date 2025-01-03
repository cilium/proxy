#pragma once

#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/common/optref.h"
#include "envoy/common/time.h"
#include "envoy/http/filter.h"
#include "envoy/http/header_map.h"
#include "envoy/http/metadata_interface.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/l7policy.pb.h"

namespace Envoy {
namespace Cilium {

/**
 * All Cilium L7 filter stats. @see stats_macros.h
 */
// clang-format off
#define ALL_CILIUM_STATS(COUNTER)	\
  COUNTER(access_denied)
// clang-format on

/**
 * Struct definition for all Cilium L7 filter stats. @see stats_macros.h
 */
struct FilterStats {
  ALL_CILIUM_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Per listener configuration for Cilium HTTP filter. This
 * is accessed by multiple working thread instances of the filter.
 */
class Config : public Logger::Loggable<Logger::Id::filter> {
public:
  Config(const std::string& access_log_path, const std::string& denied_403_body,
         TimeSource& time_source, Stats::Scope& scope, bool is_upstream);
  Config(const ::cilium::L7Policy& config, TimeSource& time_source, Stats::Scope& scope,
         bool is_upstream);

  void Log(AccessLog::Entry&, ::cilium::EntryType);

  TimeSource& time_source_;
  FilterStats stats_;
  std::string denied_403_body_;
  bool is_upstream_;

private:
  Cilium::AccessLogSharedPtr access_log_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

// Each request gets their own instance of this filter, and
// they can run parallel from multiple worker threads, all accessing
// the shared configuration.
class AccessFilter : public Http::StreamFilter,
                     Logger::Loggable<Logger::Id::filter>,
                     public Http::UpstreamCallbacks {
public:
  AccessFilter(ConfigSharedPtr& config) : config_(config) {}

  // UpstreamCallbacks
  void onUpstreamConnectionEstablished() override;

  // Http::StreamFilterBase
  void onStreamComplete() override;
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

  // Http::StreamEncoderFilter
  Http::Filter1xxHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override {
    return Http::Filter1xxHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers,
                                          bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override {}
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }

private:
  void sendLocalError(absl::string_view details);

  ConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* callbacks_ = nullptr;

  bool allowed_ = false;
  AccessLog::Entry* log_entry_ = nullptr;

  OptRef<Http::RequestHeaderMap> latched_headers_;
  absl::optional<bool> latched_end_stream_;
};

} // namespace Cilium
} // namespace Envoy
