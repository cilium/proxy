#include "cilium/websocket.h"

#include <http_parser.h>

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/registry/registry.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/filter_config.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"
#include "source/common/http/headers.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/common/protobuf/utility.h"
#include "source/common/stream_info/bool_accessor_impl.h"
#include "source/common/tcp_proxy/tcp_proxy.h"

#include "absl/status/statusor.h"
#include "cilium/api/websocket.pb.h"
#include "cilium/api/websocket.pb.validate.h" // IWYU pragma: keep
#include "cilium/socket_option_cilium_policy.h"
#include "cilium/websocket_codec.h"
#include "cilium/websocket_config.h"

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
  absl::StatusOr<Network::FilterFactoryCb>
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
 * Config registration for the WebSocket client filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumWebSocketClientConfigFactory
    : public Server::Configuration::NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  absl::StatusOr<Network::FilterFactoryCb>
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::WebSocket::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::WebSocketClient&>(
            proto_config, context.messageValidationVisitor()),
        context);
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

void Instance::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  callbacks_ = &callbacks;

  // Tell TcpProxy to not disable read so that we do WebSocket handshake before upstream
  // connection is established.
  // Use Mutable StateType so that tests can have both client and server filters in the same
  // filter chain.
  callbacks_->connection().streamInfo().filterState()->setData(
      TcpProxy::ReceiveBeforeConnectKey, std::make_unique<StreamInfo::BoolAccessorImpl>(true),
      StreamInfo::FilterState::StateType::Mutable, StreamInfo::FilterState::LifeSpan::Connection);
}

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(debug, "cilium.network.websocket: onNewConnection");

  std::string pod_ip;
  bool is_ingress;
  uint32_t identity, destination_identity;
  uint32_t proxy_id;

  auto& conn = callbacks_->connection();

  // Enable half close if not already enabled
  if (!conn.isHalfCloseEnabled()) {
    conn.enableHalfClose(true);
  }

  const Network::Address::InstanceConstSharedPtr& dst_address =
      conn.connectionInfoProvider().localAddress();
  const Network::Address::Ip* dip = dst_address ? dst_address->ip() : nullptr;
  const auto policy_socket_option = Cilium::GetCiliumPolicySocketOption(conn.streamInfo());
  if (policy_socket_option) {
    proxy_id = policy_socket_option->proxy_id_;
    pod_ip = policy_socket_option->pod_ip_;
    is_ingress = policy_socket_option->ingress_;
    identity = policy_socket_option->source_identity_;
    destination_identity = dip ? policy_socket_option->resolvePolicyId(dip) : 0;
  } else {
    // Default to ingress to destination address, but no security identities.
    proxy_id = 0;
    pod_ip = dip ? dip->addressAsString() : "";
    is_ingress = true;
    identity = 0;
    destination_identity = 0;
  }
  // Initialize the log entry
  log_entry_.InitFromConnection(pod_ip, proxy_id, is_ingress, identity,
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
  ENVOY_LOG(debug, "cilium.network.websocket: onData {} bytes, end_stream: {}", data.length(),
            end_stream);
  if (codec_) {
    if (config_->client_) {
      codec_->encode(data, end_stream);
    } else {
      codec_->decode(data, end_stream);
    }
  }
  // codec passes the data on via injectEncoded()/injectDecoded(), data is now empty
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus Instance::onWrite(Buffer::Instance& data, bool end_stream) {
  ENVOY_LOG(trace, "cilium.network.websocket: onWrite {} bytes, end_stream: {}", data.length(),
            end_stream);
  if (codec_) {
    if (config_->client_) {
      codec_->decode(data, end_stream);
    } else {
      codec_->encode(data, end_stream);
    }
  }
  // codec passes the data on via injectEncoded()/injectDecoded(), data is now empty
  return Network::FilterStatus::StopIteration;
}

void Instance::injectEncoded(Buffer::Instance& data, bool end_stream) {
  if (config_->client_) {
    callbacks_->injectReadDataToFilterChain(data, end_stream);
  } else {
    write_callbacks_->injectWriteDataToFilterChain(data, end_stream);
  }
}

void Instance::injectDecoded(Buffer::Instance& data, bool end_stream) {
  if (config_->client_) {
    write_callbacks_->injectWriteDataToFilterChain(data, end_stream);
  } else {
    callbacks_->injectReadDataToFilterChain(data, end_stream);
  }
}

void Instance::onHandshakeRequest(const Http::RequestHeaderMap& headers) {
  Network::Address::InstanceConstSharedPtr orig_dst_address{nullptr};
  uint32_t destination_identity = 0;
  const auto& conn = callbacks_->connection();
  const auto policy_socket_option = Cilium::GetCiliumPolicySocketOption(conn.streamInfo());
  if (policy_socket_option) {
    // resolve the original destination from 'x-envoy-original-dst-host' header to be used in the
    // access log message
    auto override_header = headers.getInline(original_dst_host_handle.handle());
    if (override_header != nullptr && !override_header->value().empty()) {
      const std::string request_override_host(override_header->value().getStringView());
      orig_dst_address =
          Network::Utility::parseInternetAddressAndPortNoThrow(request_override_host, false);
      const Network::Address::Ip* dip = orig_dst_address ? orig_dst_address->ip() : nullptr;
      if (dip) {
        destination_identity = policy_socket_option->resolvePolicyId(dip);
      }
    }
  }

  // Initialize the log entry
  log_entry_.UpdateFromRequest(destination_identity, orig_dst_address, headers);
}

} // namespace WebSocket
} // namespace Cilium
} // namespace Envoy
