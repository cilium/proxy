#include "cilium/tls_wrapper.h"

#include "cilium/network_policy.h"
#include "cilium/socket_option.h"
#include "source/common/protobuf/utility.h"
#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.validate.h"
#include "source/extensions/transport_sockets/tls/context_config_impl.h"
#include "source/extensions/transport_sockets/tls/ssl_socket.h"
#include "source/server/transport_socket_config_impl.h"

namespace Envoy {
namespace Cilium {

namespace {

using SslSocketPtr =
    std::unique_ptr<Extensions::TransportSockets::Tls::SslSocket>;

constexpr absl::string_view NotReadyReason{
    "TLS error: Secret is not supplied by SDS"};

// This SslSocketWrapper wraps a real SslSocket and hooks it up with
// TLS configuration derived from Cilium Network Policy.
class SslSocketWrapper : public Network::TransportSocket {
 public:
  SslSocketWrapper(
      Extensions::TransportSockets::Tls::InitialState state,
      const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options)
      : state_(state), transport_socket_options_(transport_socket_options) {}

  // Network::TransportSocket
  void setTransportSocketCallbacks(
      Network::TransportSocketCallbacks& callbacks) override {
    // Get the Cilium socket option from the callbacks in order to get the TLS
    // configuration
    const auto option =
        Cilium::GetSocketOption(callbacks.connection().socketOptions());
    if (option) {
      // Resolve the destination security ID and port
      uint32_t destination_identity = 0;
      uint32_t destination_port = option->port_;

      if (!option->ingress_) {
	Network::Address::InstanceConstSharedPtr dst_address =
	  state_ == Extensions::TransportSockets::Tls::InitialState::Client
	  ? callbacks.connection().connectionInfoProvider().remoteAddress()
	  : callbacks.connection().connectionInfoProvider().localAddress();
	if (dst_address) {
	  const auto dip = dst_address->ip();
	  if (dip) {
	    destination_port = dip->port();
	    destination_identity = option->resolvePolicyId(dip);
	  } else {
	    ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: Non-IP destination address: {}", dst_address->asString());
	  }
	} else {
	  ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: No destination address");
	}
      }

      auto port_policy = option->policy_->findPortPolicy(
          option->ingress_, destination_port,
          option->ingress_ ? option->identity_ : destination_identity);
      if (port_policy != nullptr) {
        Envoy::Ssl::ContextSharedPtr ctx =
            state_ == Extensions::TransportSockets::Tls::InitialState::Client
                ? port_policy->getClientTlsContext()
                : port_policy->getServerTlsContext();
        if (ctx) {
          const Envoy::Ssl::ContextConfig& config = 
              state_ == Extensions::TransportSockets::Tls::InitialState::Client
                  ? port_policy->getClientTlsContextConfig()
                  : port_policy->getServerTlsContextConfig();

          // create the underlying SslSocket
          ssl_socket_ =
              std::make_unique<Extensions::TransportSockets::Tls::SslSocket>(
                  std::move(ctx), state_, transport_socket_options_, config.createHandshaker());

          // Set the callbacks
          ssl_socket_->setTransportSocketCallbacks(callbacks);
        }
      }
    } else if (!option) {
      ENVOY_LOG_MISC(debug,
                     "cilium.tls_wrapper: Cilium socket option not found!");
    }
  }
  std::string protocol() const override {
    return ssl_socket_ ? ssl_socket_->protocol() : EMPTY_STRING;
  }
  absl::string_view failureReason() const override {
    return ssl_socket_ ? ssl_socket_->failureReason() : NotReadyReason;
  }
  bool canFlushClose() override {
    return ssl_socket_ ? ssl_socket_->canFlushClose() : true;
  }
  void closeSocket(Network::ConnectionEvent type) override {
    if (ssl_socket_) {
      ssl_socket_->closeSocket(type);
    }
  }
  Network::IoResult doRead(Buffer::Instance& buffer) override {
    if (ssl_socket_) {
      return ssl_socket_->doRead(buffer);
    }
    return {Network::PostIoAction::Close, 0, false};
  }
  Network::IoResult doWrite(Buffer::Instance& buffer,
                            bool end_stream) override {
    if (ssl_socket_) {
      return ssl_socket_->doWrite(buffer, end_stream);
    }
    return {Network::PostIoAction::Close, 0, false};
  }
  void onConnected() override {
    if (ssl_socket_) {
      ssl_socket_->onConnected();
    }
  }
  Ssl::ConnectionInfoConstSharedPtr ssl() const override {
    return ssl_socket_ ? ssl_socket_->ssl() : nullptr;
  }
  bool startSecureTransport() override {
    return ssl_socket_ ? ssl_socket_->startSecureTransport() : false;
  }

 private:
  Extensions::TransportSockets::Tls::InitialState state_;
  const Network::TransportSocketOptionsConstSharedPtr transport_socket_options_;
  SslSocketPtr ssl_socket_;
};

class ClientSslSocketFactory : public Network::TransportSocketFactory {
 public:
  Network::TransportSocketPtr createTransportSocket(
      Network::TransportSocketOptionsConstSharedPtr options) const override {
    return std::make_unique<SslSocketWrapper>(
        Extensions::TransportSockets::Tls::InitialState::Client, options);
  }

  bool implementsSecureTransport() const override { return true; }
  bool usesProxyProtocolOptions() const override { return false; }
};

class ServerSslSocketFactory : public Network::TransportSocketFactory {
 public:
  Network::TransportSocketPtr createTransportSocket(
      Network::TransportSocketOptionsConstSharedPtr options) const override {
    return std::make_unique<SslSocketWrapper>(
        Extensions::TransportSockets::Tls::InitialState::Server, options);
  }

  bool implementsSecureTransport() const override { return true; }
  bool usesProxyProtocolOptions() const override { return false; }
};

}  // namespace

Network::TransportSocketFactoryPtr
UpstreamTlsWrapperFactory::createTransportSocketFactory(
    const Protobuf::Message&,
    Server::Configuration::TransportSocketFactoryContext&) {
  return std::make_unique<ClientSslSocketFactory>();
}

ProtobufTypes::MessagePtr UpstreamTlsWrapperFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext>();
}

REGISTER_FACTORY(UpstreamTlsWrapperFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);

Network::TransportSocketFactoryPtr
DownstreamTlsWrapperFactory::createTransportSocketFactory(
    const Protobuf::Message&,
    Server::Configuration::TransportSocketFactoryContext&,
    const std::vector<std::string>&) {
  return std::make_unique<ServerSslSocketFactory>();
}

ProtobufTypes::MessagePtr
DownstreamTlsWrapperFactory::createEmptyConfigProto() {
  return std::make_unique<
      envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext>();
}

REGISTER_FACTORY(DownstreamTlsWrapperFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);
}  // namespace Cilium
}  // namespace Envoy
