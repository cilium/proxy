#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/common/random_generator.h"
#include "envoy/common/time.h"
#include "envoy/event/dispatcher.h"
#include "envoy/http/request_id_extension.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/logger.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/websocket.pb.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

/**
 * All WebSocket filter stats. @see stats_macros.h
 */
// clang-format off
#define ALL_WEBSOCKET_STATS(COUNTER)		\
  COUNTER(access_denied)			\
  COUNTER(protocol_error)			\
  COUNTER(handshake_timeout)			\
  COUNTER(handshake_not_http)			\
  COUNTER(handshake_too_large)			\
  COUNTER(handshake_parse_error)      		\
  COUNTER(handshake_invalid_http_version)	\
  COUNTER(handshake_invalid_http_status)	\
  COUNTER(handshake_invalid_websocket_request)	\
  COUNTER(handshake_invalid_websocket_response)	\
  COUNTER(handshake_write_error)		\
  COUNTER(ping_sent_count)                                                                                \
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
  Config(Server::Configuration::FactoryContext& context, bool client,
         const std::string& access_log_path, const std::string& host, const std::string& path,
         const std::string& key, const std::string& version, const std::string& origin,
         const ProtobufWkt::Duration& handshake_timeout, const ProtobufWkt::Duration& ping_interval,
         bool ping_when_idle);
  Config(const ::cilium::WebSocketClient& config, Server::Configuration::FactoryContext& context);
  Config(const ::cilium::WebSocketServer& config, Server::Configuration::FactoryContext& context);

  static std::string keyResponse(absl::string_view key);

  void Log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

  TimeSource& time_source_;
  Event::Dispatcher& dispatcher_;
  FilterStats stats_;
  Random::RandomGenerator& random_;
  Http::RequestIDExtensionSharedPtr request_id_extension_;
  bool client_;

  std::string host_;
  std::string path_;
  std::string key_;
  std::string version_;
  std::string origin_;
  std::chrono::milliseconds handshake_timeout_;
  std::chrono::milliseconds ping_interval_;
  bool ping_when_idle_;

  static std::vector<uint8_t> getSha1Digest(const Buffer::Instance&);

private:
  Cilium::AccessLogSharedPtr access_log_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
