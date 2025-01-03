#include "cilium/tls_wrapper.h"

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.validate.h"

#include "source/common/network/raw_buffer_socket.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/ssl_socket.h"

#include "cilium/api/tls_wrapper.pb.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option.h"

namespace Envoy {
namespace Cilium {

namespace {

constexpr absl::string_view NotReadyReason{"TLS error: Secret is not supplied by SDS"};

// This SslSocketWrapper wraps a real SslSocket and hooks it up with
// TLS configuration derived from Cilium Network Policy.
class SslSocketWrapper : public Network::TransportSocket {
public:
  SslSocketWrapper(Extensions::TransportSockets::Tls::InitialState state,
                   const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options)
      : state_(state), transport_socket_options_(transport_socket_options) {}

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override {
    // Get the Cilium socket option from the callbacks in order to get the TLS
    // configuration
    // Cilium socket option is only created if the (intial) policy for the local pod exists.
    // If the policy requires TLS then a TLS socket is used, but if the policy does not require
    // TLS a raw socket is used instead,
    const auto option = Cilium::GetSocketOption(callbacks.connection().socketOptions());
    if (option) {
      const auto& policy = option->getPolicy();
      if (!policy) {
        ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: No policy found for pod {}", option->pod_ip_);
        return;
      }
      // Resolve the destination security ID and port
      uint32_t destination_identity = 0;
      uint32_t destination_port = option->port_;
      const Network::Address::Ip* dip = nullptr;
      bool is_client = state_ == Extensions::TransportSockets::Tls::InitialState::Client;

      if (!option->ingress_) {
        Network::Address::InstanceConstSharedPtr dst_address =
            is_client ? callbacks.connection().connectionInfoProvider().remoteAddress()
                      : callbacks.connection().connectionInfoProvider().localAddress();
        if (dst_address) {
          dip = dst_address->ip();
          if (dip) {
            destination_port = dip->port();
            destination_identity = option->resolvePolicyId(dip);
          } else {
            ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: Non-IP destination address: {}",
                           dst_address->asString());
          }
        } else {
          ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: No destination address");
        }
      }

      // get the requested server name from the connection, if any
      const auto& sni = option->sni_;

      auto remote_id = option->ingress_ ? option->identity_ : destination_identity;
      auto port_policy = policy->findPortPolicy(option->ingress_, destination_port);
      const Envoy::Ssl::ContextConfig* config = nullptr;
      bool raw_socket_allowed = false;
      Envoy::Ssl::ContextSharedPtr ctx =
          is_client ? port_policy.getClientTlsContext(remote_id, sni, &config, raw_socket_allowed)
                    : port_policy.getServerTlsContext(remote_id, sni, &config, raw_socket_allowed);
      if (ctx) {
        // create the underlying SslSocket
        auto status_or_socket = Extensions::TransportSockets::Tls::SslSocket::create(
            std::move(ctx), state_, transport_socket_options_, config->createHandshaker());
        if (status_or_socket.ok()) {
          socket_ = std::move(status_or_socket.value());
          // Set the callbacks
          socket_->setTransportSocketCallbacks(callbacks);
        } else {
          ENVOY_LOG_MISC(error, "Unable to create ssl socket {}",
                         status_or_socket.status().message());
        }
      } else if (config == nullptr && raw_socket_allowed) {
        // Use RawBufferSocket when policy allows without TLS.
        // If policy has TLS context config then a raw socket must NOT be used.
        socket_ = std::make_unique<Network::RawBufferSocket>();
        // Set the callbacks
        socket_->setTransportSocketCallbacks(callbacks);
      } else {
        policy->tlsWrapperMissingPolicyInc();

        std::string ipStr("<none>");
        if (option->ingress_) {
          Network::Address::InstanceConstSharedPtr src_address =
              is_client ? callbacks.connection().connectionInfoProvider().localAddress()
                        : callbacks.connection().connectionInfoProvider().remoteAddress();
          if (src_address) {
            const auto sip = src_address->ip();
            if (sip) {
              ipStr = sip->addressAsString();
            }
          }
        } else {
          if (dip) {
            ipStr = dip->addressAsString();
          }
        }
        ENVOY_LOG_MISC(
            warn,
            "cilium.tls_wrapper: Could not get {} TLS context for pod {} on {} IP {} (id {}) port "
            "{} sni \"{}\" and raw socket is not allowed",
            is_client ? "client" : "server", option->pod_ip_,
            option->ingress_ ? "source" : "destination", ipStr, remote_id, destination_port, sni);
      }
    } else {
      ENVOY_LOG_MISC(warn, "cilium.tls_wrapper: Can not correlate connection with Cilium Network "
                           "Policy (Cilium socket option not found)");
    }
  }

  std::string protocol() const override { return socket_ ? socket_->protocol() : EMPTY_STRING; }
  absl::string_view failureReason() const override {
    return socket_ ? socket_->failureReason() : NotReadyReason;
  }
  bool canFlushClose() override { return socket_ ? socket_->canFlushClose() : true; }

  // Override if need to intercept client socket connect() call.
  // Api::SysCallIntResult connect(Network::ConnectionSocket& socket) override

  void closeSocket(Network::ConnectionEvent type) override {
    if (socket_) {
      socket_->closeSocket(type);
    }
  }
  Network::IoResult doRead(Buffer::Instance& buffer) override {
    if (socket_) {
      return socket_->doRead(buffer);
    }
    return {Network::PostIoAction::Close, 0, false};
  }
  Network::IoResult doWrite(Buffer::Instance& buffer, bool end_stream) override {
    if (socket_) {
      return socket_->doWrite(buffer, end_stream);
    }
    return {Network::PostIoAction::Close, 0, false};
  }
  void onConnected() override {
    if (socket_) {
      socket_->onConnected();
    }
  }
  Ssl::ConnectionInfoConstSharedPtr ssl() const override {
    return socket_ ? socket_->ssl() : nullptr;
  }
  bool startSecureTransport() override { return socket_ ? socket_->startSecureTransport() : false; }
  void configureInitialCongestionWindow(uint64_t bandwidth_bits_per_sec,
                                        std::chrono::microseconds rtt) override {
    if (socket_) {
      socket_->configureInitialCongestionWindow(bandwidth_bits_per_sec, rtt);
    }
  }

private:
  Extensions::TransportSockets::Tls::InitialState state_;
  const Network::TransportSocketOptionsConstSharedPtr transport_socket_options_;
  Network::TransportSocketPtr socket_{nullptr};
};

class ClientSslSocketFactory : public Network::CommonUpstreamTransportSocketFactory {
public:
  Network::TransportSocketPtr
  createTransportSocket(Network::TransportSocketOptionsConstSharedPtr options,
                        std::shared_ptr<const Upstream::HostDescription>) const override {
    return std::make_unique<SslSocketWrapper>(
        Extensions::TransportSockets::Tls::InitialState::Client, options);
  }

  absl::string_view defaultServerNameIndication() const override { return EMPTY_STRING; }

  bool implementsSecureTransport() const override { return true; }
};

class ServerSslSocketFactory : public Network::DownstreamTransportSocketFactory {
public:
  Network::TransportSocketPtr createDownstreamTransportSocket() const override {
    return std::make_unique<SslSocketWrapper>(
        Extensions::TransportSockets::Tls::InitialState::Server, nullptr);
  }

  bool implementsSecureTransport() const override { return true; }
};

} // namespace

absl::StatusOr<Network::UpstreamTransportSocketFactoryPtr>
UpstreamTlsWrapperFactory::createTransportSocketFactory(
    const Protobuf::Message&, Server::Configuration::TransportSocketFactoryContext&) {
  return std::make_unique<ClientSslSocketFactory>();
}

ProtobufTypes::MessagePtr UpstreamTlsWrapperFactory::createEmptyConfigProto() {
  return std::make_unique<::cilium::UpstreamTlsWrapperContext>();
}

REGISTER_FACTORY(UpstreamTlsWrapperFactory,
                 Server::Configuration::UpstreamTransportSocketConfigFactory);

absl::StatusOr<Network::DownstreamTransportSocketFactoryPtr>
DownstreamTlsWrapperFactory::createTransportSocketFactory(
    const Protobuf::Message&, Server::Configuration::TransportSocketFactoryContext&,
    const std::vector<std::string>&) {
  return std::make_unique<ServerSslSocketFactory>();
}

ProtobufTypes::MessagePtr DownstreamTlsWrapperFactory::createEmptyConfigProto() {
  return std::make_unique<::cilium::DownstreamTlsWrapperContext>();
}

REGISTER_FACTORY(DownstreamTlsWrapperFactory,
                 Server::Configuration::DownstreamTransportSocketConfigFactory);
} // namespace Cilium
} // namespace Envoy
