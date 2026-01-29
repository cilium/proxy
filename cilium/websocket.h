#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/event/schedulable_cb.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/logger.h"

#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/websocket_codec.h"
#include "cilium/websocket_config.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

class Instance : public Network::Filter,
                 public CodecCallbacks,
                 Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config) : config_(config) {}

  // Network::ReadFilter
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;
  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onData(Buffer::Instance&, bool end_stream) override;

  // Network::WriteFilter
  void initializeWriteFilterCallbacks(Network::WriteFilterCallbacks& callbacks) override {
    write_callbacks_ = &callbacks;
  }
  Network::FilterStatus onWrite(Buffer::Instance&, bool end_stream) override;

  // WebSocket::CodecCallbacks
  const ConfigSharedPtr& config() override { return config_; }
  void onHandshakeCreated(const Http::RequestHeaderMap& headers) override {
    log_entry_.updateFromRequest(0, nullptr, headers);
  }
  void onHandshakeSent() override { config_->log(log_entry_, ::cilium::EntryType::Request); }
  void onHandshakeRequest(const Http::RequestHeaderMap& headers) override;
  void onHandshakeResponse(const Http::ResponseHeaderMap& headers) override {
    log_entry_.updateFromResponse(headers, config_->time_source_);
    config_->log(log_entry_, ::cilium::EntryType::Response);
  }
  void onHandshakeResponseSent(const Http::ResponseHeaderMap& headers) override {
    bool accepted = headers.Status() && headers.getStatusValue() == "101";
    if (accepted) {
      config_->log(log_entry_, ::cilium::EntryType::Request);
    } else {
      config_->log(log_entry_, ::cilium::EntryType::Denied);
      config_->stats_.access_denied_.inc();
    }
    log_entry_.updateFromResponse(headers, config_->time_source_);
    config_->log(log_entry_, ::cilium::EntryType::Response);
  }

  void injectEncoded(Buffer::Instance& data, bool end_stream) override;
  void injectDecoded(Buffer::Instance& data, bool end_stream) override;

  void
  setOriginalDestinationAddress(const Network::Address::InstanceConstSharedPtr& orig_dst) override {
    callbacks_->connection().connectionInfoSetter().restoreLocalAddress(orig_dst);
  }

private:
  const ConfigSharedPtr config_;

  Network::ReadFilterCallbacks* callbacks_{nullptr};
  Network::WriteFilterCallbacks* write_callbacks_{nullptr};
  CodecPtr codec_{nullptr};
  Event::SchedulableCallbackPtr client_handshake_cb_{nullptr};
  bool handshake_timer_started_{false};
  Cilium::AccessLog::Entry log_entry_{};
};

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
