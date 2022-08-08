#pragma once

#include <string>

#include "cilium/websocket_config.h"

#include "envoy/event/dispatcher.h"
#include "envoy/event/timer.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

class CodecCallbacks {
public:
  virtual ~CodecCallbacks() = default;

  virtual const ConfigSharedPtr& config() PURE;

  virtual void injectEncoded(Buffer::Instance& data, bool end_stream) PURE;
  virtual void injectDecoded(Buffer::Instance& data, bool end_stream) PURE;

  virtual void setOriginalDestinationAddress(const Network::Address::InstanceConstSharedPtr& orig_dst) PURE;

  virtual void onHandshakeCreated(const Http::RequestHeaderMap&) PURE;
  virtual void onHandshakeSent() PURE;
  virtual void onHandshakeRequest(const Http::RequestHeaderMap& headers) PURE;
  virtual void onHandshakeResponse(const Http::ResponseHeaderMap& headers) PURE;
  virtual void onHandshakeResponseSent(const Http::ResponseHeaderMap& headers) PURE;
};

class Codec : Logger::Loggable<Logger::Id::filter> {
public:
  Codec(CodecCallbacks* parent, Network::Connection& conn);

  void handshake();
  void encode(Buffer::Instance&, bool end_stream);
  void decode(Buffer::Instance&, bool end_stream);

private:
  class Encoder : Logger::Loggable<Logger::Id::filter> {
  public:
    Encoder(Codec& parent) : parent_(parent) {}

    void encode(Buffer::Instance&, bool end_stream, uint8_t opcode);

    size_t hasData() { return encoded_.length() > 0; }
    Buffer::Instance& data() { return encoded_; }
    bool endStream() { return end_stream_; }
    void drain() { encoded_.drain(encoded_.length()); }

    Codec& parent_;
    bool end_stream_{false};
    Buffer::OwnedImpl encoded_{};  // Buffer for encoded websocket frames
  };

  class Decoder : Logger::Loggable<Logger::Id::filter> {
  public:
    Decoder(Codec& parent) : parent_(parent) {}

    void decode(Buffer::Instance& data, bool end_stream);

    size_t hasData() { return decoded_.length() > 0; }
    Buffer::Instance& data() { return decoded_; }
    bool endStream() { return end_stream_; }
    void drain() { decoded_.drain(decoded_.length()); }

    Codec& parent_;
    bool end_stream_{false};
    Buffer::OwnedImpl buffer_{};  // Buffer for partial websocket frames
    Buffer::OwnedImpl decoded_{}; // Buffer for decoded websocket frames

    bool unmasking_{false};
    uint8_t mask_[4];
    size_t payload_offset_{0};
    size_t payload_remaining_{0};
  };

  void startPingTimer();
  void resetPingTimer() {
    if (ping_timer_ != nullptr) {
      auto config = parent_->config();
      if (config->ping_when_idle_) {
	ping_timer_->enableTimer(config->ping_interval_);
      }
    }
  }

  bool ping(const void *payload, size_t len);
  bool pong(const void *payload, size_t len);

  static Network::Address::InstanceConstSharedPtr decodeHandshakeRequest(const ConfigSharedPtr& config, const Http::RequestHeaderMap& headers);
  static void encodeHandshakeResponse(Http::ResponseHeaderMap& headers, uint32_t status, absl::string_view hash, const Http::RequestHeaderMap* request_headers);

  const ConfigSharedPtr& config() { return parent_->config(); };

  static bool checkPrefix(Buffer::Instance& data, const std::string& prefix);

  void closeOnError(const char *msg);
  void closeOnError(Buffer::Instance& data, const char *msg);


  CodecCallbacks* parent_;
  Network::Connection& connection_;
  Encoder encoder_;
  Decoder decoder_;

  Event::TimerPtr ping_timer_{nullptr};
  uint32_t ping_interval_jitter_percent_{15};
  uint64_t ping_count_{0};

  Event::TimerPtr handshake_timer_{nullptr};
  Buffer::OwnedImpl handshake_buffer_{};
  bool accepted_{false};
};
typedef std::unique_ptr<Codec> CodecPtr;

}  // namespace WebSocket
}  // namespace Cilium
}  // namespace Envoy
