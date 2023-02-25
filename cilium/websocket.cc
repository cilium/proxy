#include "cilium/websocket.h"

#include <http_parser.h>

#include <string>

#include "envoy/registry/registry.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/assert.h"
#include "source/common/common/base64.h"
#include "source/common/common/enum_to_int.h"
#include "source/common/common/hex.h"
#include "source/common/crypto/crypto_impl.h"
#include "source/common/crypto/utility.h"
#include "source/common/http/header_map_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/http/utility.h"
#include "source/common/network/filter_manager_impl.h"
#include "source/common/network/utility.h"

#include "cilium/api/websocket.pb.validate.h"
#include "cilium/socket_option.h"
#include "cilium/websocket_protocol.h"

namespace Envoy {
namespace Cilium {
namespace WebSocket {

namespace {

Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    origin_handle(Http::CustomHeaders::get().Origin);
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    original_dst_host_handle(Http::Headers::get().EnvoyOriginalDstHost);
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_key_handle(Http::LowerCaseString{"sec-websocket-key"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_version_handle(Http::LowerCaseString{"sec-websocket-version"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_protocol_handle(Http::LowerCaseString{"sec-websocket-protocol"});
Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::RequestHeaders>
    sec_websocket_extensions_handle(Http::LowerCaseString{"sec-websocket-extensions"});

Http::RegisterCustomInlineHeader<Http::CustomInlineHeaderRegistry::Type::ResponseHeaders>
    sec_websocket_accept_handle(Http::LowerCaseString{"sec-websocket-accept"});

} // namespace

/**
 * Config registration for the WebSocket server filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumWebSocketServerConfigFactory
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocketServer&>(
            proto_config, context.messageValidationVisitor()),
        context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(std::make_shared<Cilium::WebSocket::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocketServer>();
  }

  std::string name() const override { return "cilium.network.websocket.server"; }
};

/**
 * Static registration for the websocket server network filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumWebSocketServerConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

/**
 * Config registration for the downstream WebSocket client filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumWebSocketClientConfigFactory
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocketClient&>(
            proto_config, context.messageValidationVisitor()),
        false, context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(std::make_shared<Cilium::WebSocket::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocketClient>();
  }

  std::string name() const override { return "cilium.network.websocket.client"; }
};

/**
 * Static registration for the websocket client network filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumWebSocketClientConfigFactory,
                 Server::Configuration::NamedNetworkFilterConfigFactory);

/**
 * Config registration for the upstream WebSocket client filter. @see
 * NamedUpstreamNetworkFilterConfigFactory.
 */
class CiliumUpstreamWebSocketClientConfigFactory
    : public Server::Configuration::NamedUpstreamNetworkFilterConfigFactory {
public:
  // NamedUpstreamNetworkFilterConfigFactory
  Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Server::Configuration::CommonFactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocketClient&>(
            proto_config, context.messageValidationVisitor()),
        true, context);
    return [config](Network::FilterManager& filter_manager) mutable -> void {
      filter_manager.addFilter(std::make_shared<Cilium::WebSocket::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::WebSocketClient>();
  }

  std::string name() const override { return "cilium.network.websocket.client"; }
};

/**
 * Static registration for the websocket client network filter. @see RegisterFactory.
 */
REGISTER_FACTORY(CiliumUpstreamWebSocketClientConfigFactory,
                 Server::Configuration::NamedUpstreamNetworkFilterConfigFactory);

Network::FilterStatus Instance::onNewConnection() {
  // Return immediately if already called
  if (codec_)
    return Network::FilterStatus::Continue;

  auto& conn = callbacks_->connection();
  ENVOY_CONN_LOG(debug, "cilium.network.websocket: onNewConnection", conn);

  std::string pod_ip;
  bool is_ingress;
  uint32_t identity, destination_identity;

  // Enable half close if not already enabled
  if (!conn.isHalfCloseEnabled()) {
    conn.enableHalfClose(true);
  }

  const Network::Address::InstanceConstSharedPtr& dst_address =
      conn.connectionInfoProvider().localAddress();
  const Network::Address::Ip* dip = dst_address ? dst_address->ip() : nullptr;
  const Network::Socket::OptionsSharedPtr socketOptions = conn.socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (option) {
    pod_ip = option->pod_ip_;
    is_ingress = option->ingress_;
    identity = option->identity_;
    destination_identity = dip ? option->resolvePolicyId(dip) : 0;
  } else {
    // Default to ingress to destination address, but no security identities.
    pod_ip = dip ? dip->addressAsString() : "";
    is_ingress = true;
    identity = 0;
    destination_identity = 0;
  }
  // Initialize the log entry
  log_entry_.InitFromConnection(pod_ip, is_ingress, identity,
                                callbacks_->connection().connectionInfoProvider().remoteAddress(),
                                destination_identity, dst_address, &config_->time_source_);

  codec_ = std::make_unique<Codec>(this, conn);

  if (!config_->client_) {
    // Server allows upstream processing only after the handshake has been received
    return Network::FilterStatus::StopIteration;
  }

  // Handshake cannot be injected while in this (onNewConnection()) callbask, schedule it to be run
  // afterwards, but during the current dispatcher iteration.
  client_handshake_cb_ =
      conn.dispatcher().createSchedulableCallback([this]() { codec_->handshake(); });
  client_handshake_cb_->scheduleCallbackCurrentIteration();

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(debug, "cilium.network.websocket: onData {} bytes, end_stream: {}",
                 callbacks_->connection(), data.length(), end_stream);
#ifdef NO_ENVOY_UPSTREAM_PATCH
  // Upstream filters do not seem to get the onNewConnection call
  if (!codec_) {
    onNewConnection(); // initializes codec_
  }
#endif
  if (codec_) {
    // Upstream client decodes when reading data via onData()
    if (config_->client_ && !config_->upstream_) {
      codec_->encode(data, end_stream);
    } else {
      codec_->decode(data, end_stream);
    }
  }
  // codec passes the data on via injectEncoded()/injectDecoded(), data is now empty
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Instance::onWrite(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(trace, "cilium.network.websocket: onWrite {} bytes, end_stream: {}",
                 callbacks_->connection(), data.length(), end_stream);
  // Upstream filters do not seem to get the onNewConnection call
  if (!codec_) {
    onNewConnection(); // initializes codec_
  }
  if (codec_) {
    // Upstream client encodes when writing data via onWrite()
    if (config_->client_ && !config_->upstream_) {
      codec_->decode(data, end_stream);
    } else {
      codec_->encode(data, end_stream);
    }
  }
  // codec passes the data on via injectEncoded()/injectDecoded(), data is now empty
  return Network::FilterStatus::StopIteration;
}

void Instance::injectEncoded(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(debug, "cilium.network.websocket: injectEncoded {} bytes, end_stream: {}",
                 callbacks_->connection(), data.length(), end_stream);
  if (config_->client_ && !config_->upstream_) {
    callbacks_->injectReadDataToFilterChain(data, end_stream);
  } else {
    write_callbacks_->injectWriteDataToFilterChain(data, end_stream);
  }
}

void Instance::injectDecoded(Buffer::Instance& data, bool end_stream) {
  ENVOY_CONN_LOG(debug, "cilium.network.websocket: injectDecoded {} bytes, end_stream: {}",
                 callbacks_->connection(), data.length(), end_stream);
  if (config_->client_ && !config_->upstream_) {
    write_callbacks_->injectWriteDataToFilterChain(data, end_stream);
  } else {
    callbacks_->injectReadDataToFilterChain(data, end_stream);
  }
}

void Instance::onHandshakeRequest(const Http::RequestHeaderMap& headers) {
  ENVOY_CONN_LOG(debug, "cilium.network.websocket: onHandshakeRequest: {}",
                 callbacks_->connection(), headers);
  Network::Address::InstanceConstSharedPtr orig_dst_address{nullptr};
  uint32_t destination_identity = 0;
  const auto& conn = callbacks_->connection();
  const Network::Socket::OptionsSharedPtr socketOptions = conn.socketOptions();
  const auto option = Cilium::GetSocketOption(socketOptions);
  if (option) {
    // resolve the original destination from 'x-envoy-original-dst-host' header to be used in the
    // access log message
    auto override_header = headers.getInline(original_dst_host_handle.handle());
    if (override_header != nullptr && !override_header->value().empty()) {
      const std::string request_override_host(override_header->value().getStringView());
      orig_dst_address =
          Network::Utility::parseInternetAddressAndPortNoThrow(request_override_host, false);
      const Network::Address::Ip* dip = orig_dst_address ? orig_dst_address->ip() : nullptr;
      if (dip) {
        destination_identity = option->resolvePolicyId(dip);
      }
    }
  }

  // Initialize the log entry
  log_entry_.UpdateFromRequest(destination_identity, orig_dst_address, headers);
}

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
