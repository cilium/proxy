#include "cilium/websocket_config.h"

#include <http_parser.h>
#include <openssl/digest.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/common/exception.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/extensions/request_id/uuid/v3/uuid.pb.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/http/request_id_extension_impl.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/common/protobuf/utility.h"

#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/websocket.pb.h"
#include "cilium/websocket_protocol.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

std::vector<uint8_t> Config::getSha1Digest(const Buffer::Instance& buffer) {
  std::vector<uint8_t> digest(SHA_DIGEST_LENGTH);
  bssl::ScopedEVP_MD_CTX ctx;
  auto rc = EVP_DigestInit(ctx.get(), EVP_sha1());
  RELEASE_ASSERT(rc == 1, "Failed to init digest context");
  for (const auto& slice : buffer.getRawSlices()) {
    rc = EVP_DigestUpdate(ctx.get(), slice.mem_, slice.len_);
    RELEASE_ASSERT(rc == 1, "Failed to update digest");
  }
  rc = EVP_DigestFinal(ctx.get(), digest.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");
  return digest;
}

Config::Config(Server::Configuration::FactoryContext& context, bool client,
               const std::string& access_log_path, const std::string& host, const std::string& path,
               const std::string& key, const std::string& version, const std::string& origin,
               const ProtobufWkt::Duration& handshake_timeout,
               const ProtobufWkt::Duration& ping_interval, bool ping_when_idle)
    : time_source_(context.serverFactoryContext().timeSource()),
      dispatcher_(context.serverFactoryContext().mainThreadDispatcher()),
      stats_{ALL_WEBSOCKET_STATS(POOL_COUNTER_PREFIX(context.scope(), "websocket"))},
      random_(context.serverFactoryContext().api().randomGenerator()), client_(client),
      host_(absl::AsciiStrToLower(host)), path_(absl::AsciiStrToLower(path)), key_(key),
      version_(absl::AsciiStrToLower(version)), origin_(absl::AsciiStrToLower(origin)),
      handshake_timeout_(std::chrono::seconds(5)), ping_interval_(std::chrono::milliseconds(0)),
      ping_when_idle_(ping_when_idle), access_log_(nullptr) {
  envoy::extensions::filters::network::http_connection_manager::v3::RequestIDExtension x_rid_config;
  x_rid_config.mutable_typed_config()->PackFrom(
      envoy::extensions::request_id::uuid::v3::UuidRequestIdConfig());
  auto extension_or_error = Http::RequestIDExtensionFactory::fromProto(x_rid_config, context);
  THROW_IF_NOT_OK_REF(extension_or_error.status());
  request_id_extension_ = extension_or_error.value();

  // Base64 encode the given/expected key, if any.
  if (!key_.empty()) {
    key_ = Base64::encode(key_.data(), key_.length());
  }

  if (!access_log_path.empty()) {
    access_log_ = AccessLog::Open(access_log_path, time_source_);
  }

  const uint64_t timeout = DurationUtil::durationToMilliseconds(handshake_timeout);
  if (timeout > 0) {
    handshake_timeout_ = std::chrono::milliseconds(timeout);
  }

  const uint64_t interval = DurationUtil::durationToMilliseconds(ping_interval);
  if (interval > 0) {
    ping_interval_ = std::chrono::milliseconds(interval);
  } else if (ping_when_idle_) {
    throw EnvoyException(
        "cilium.network.websocket: ping_when_idle requires ping_interval to be set.");
  }
}

Config::Config(const ::cilium::WebSocketClient& config,
               Server::Configuration::FactoryContext& context)
    : Config(context, true /* client */, config.access_log_path(), config.host(), config.path(),
             config.key(), config.version(), config.origin(), config.handshake_timeout(),
             config.ping_interval(), config.ping_when_idle()) {
  // Client defaults
  if (host_.empty()) {
    throw EnvoyException("cilium.network.websocket.client: host must be non-empty.");
  }

  if (path_.empty()) {
    path_ = "/";
  }
  if (version_.empty()) {
    version_ = "13";
  }
  if (key_.empty()) {
    uint64_t random[2]; // 16 bytes
    for (size_t i = 0; i < sizeof(random) / sizeof(random[0]); i++) {
      random[i] = random_.random();
    }
    key_ = Base64::encode(reinterpret_cast<char*>(random), sizeof(random));
  }
}

Config::Config(const ::cilium::WebSocketServer& config,
               Server::Configuration::FactoryContext& context)
    : Config(context, false /* server */, config.access_log_path(), config.host(), config.path(),
             config.key(), config.version(), config.origin(), config.handshake_timeout(),
             config.ping_interval(), config.ping_when_idle()) {}

// Compute expected key response
std::string Config::keyResponse(absl::string_view key) {
  Buffer::OwnedImpl buf(key.data(), key.length());
  buf.add(WEBSOCKET_GUID);
  auto sha1 = getSha1Digest(buf);
  return Base64::encode(reinterpret_cast<char*>(sha1.data()), sha1.size());
}

void Config::Log(AccessLog::Entry& entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
