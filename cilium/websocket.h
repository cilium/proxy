#pragma once

#include <string>

#include "absl/types/optional.h"

#include "cilium/accesslog.h"
#include "cilium/api/websocket.pb.h"

#include "envoy/event/dispatcher.h"
#include "envoy/event/schedulable_cb.h"
#include "envoy/event/timer.h"
#include "envoy/common/random_generator.h"
#include "envoy/server/filter_config.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

/**
 * All WebSocket filter stats. @see stats_macros.h
 */
// clang-format off
#define ALL_WEBSOCKET_STATS(COUNTER)   \
  COUNTER(access_denied)	       \
  COUNTER(protocol_error)	       \
// clang-format on

/**
 * Struct definition for all WebSocket filter stats. @see stats_macros.h
 */
struct FilterStats {
  ALL_WEBSOCKET_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Per listener configuration for Cilium HTTP filter. This
 * is accessed by multiple working thread instances of the filter.
 */
class Config : public Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::WebSocket& config, Server::Configuration::FactoryContext& context,
	 bool client);
  ~Config();

  void Log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

  TimeSource& time_source_;
  Event::Dispatcher& dispatcher_;
  FilterStats stats_;
  Random::RandomGenerator& random_;
  bool client_;
  uint8_t data_opcode_;

  std::string expected_host_;
  std::string expected_path_;
  std::string expected_key_;
  std::string expected_version_;
  std::string expected_origin_;
  std::string expected_key_accept_;

private:
  Cilium::AccessLog* access_log_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

class Instance : public Network::Filter, Logger::Loggable<Logger::Id::filter> {
 public:
  Instance(const ConfigSharedPtr& config) :
    config_(config),
    handshake_timer_(nullptr),
    handshake_timeout_(std::chrono::seconds(60)),
    ping_timer_(nullptr),
    ping_interval_(std::chrono::seconds(10)),
    ping_interval_jitter_percent_(15.0),
    encode_opcode_(config->data_opcode_) {}

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance&, bool end_stream) override;

private:
  Network::FilterStatus closeOnError(const char *msg);

  const ConfigSharedPtr config_;
  Event::TimerPtr handshake_timer_;
  std::chrono::milliseconds handshake_timeout_;
  Event::TimerPtr ping_timer_;
  std::chrono::milliseconds ping_interval_;
  uint32_t ping_interval_jitter_percent_;
  uint64_t ping_count_{0};

  Network::ReadFilterCallbacks* callbacks_{nullptr};

  bool handshake_sent_{false};
  bool accepted_{false};
  bool closed_{false};
  bool decode_end_stream_{false};
  bool encode_end_stream_{false};
  Buffer::OwnedImpl handshake_buffer_{};  // Buffer for websocket handshake
  Buffer::OwnedImpl decode_buffer_{};  // Buffer for partial websocket frame
  Buffer::OwnedImpl encoded_buffer_{};  // Buffer for partial websocket frame
  uint8_t encode_opcode_;

  union {
    uint8_t bytes[4];
    uint32_t word;
  } mask_;
  bool decoder_unmasking_{false};
  size_t payload_offset_{0};
  size_t payload_remaining_{0};

  Cilium::AccessLog::Entry log_entry_{};
};

class Filter : public Http::StreamFilter,
  Logger::Loggable<Logger::Id::filter> {
public:
  Filter(ConfigSharedPtr& config) : config_(config), encode_opcode_(config->data_opcode_) {}

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::RequestHeaderMap& headers, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  Http::FilterTrailersStatus decodeTrailers(Http::RequestTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode1xxHeaders(Http::ResponseHeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::ResponseHeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override;
  Http::FilterTrailersStatus encodeTrailers(Http::ResponseTrailerMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override {}
  Http::FilterMetadataStatus encodeMetadata(Http::MetadataMap&) override {
    return Http::FilterMetadataStatus::Continue;
  }

private:
  void maskData(uint8_t *buf, size_t n_bytes);

  ConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* callbacks_;

  bool upgrade_{false};
  bool accepted_{false};
  bool closed_{false};
  bool decode_end_stream_{false};
  bool encode_end_stream_{false};
  Buffer::OwnedImpl buffer_{};  // Buffer for partial websocket frame
  uint8_t encode_opcode_;

  union {
    uint8_t bytes[4];
    uint32_t word;
  } mask_;
  size_t payload_offset_{0};
  size_t payload_remaining_{0};

  Cilium::AccessLog::Entry log_entry_{};
};

}  // namespace WebSocket
}  // namespace Cilium
}  // namespace Envoy
