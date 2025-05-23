#include "cilium/tls_wrapper.h"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/network/address.h"
#include "envoy/network/post_io_action.h"
#include "envoy/network/transport_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/ssl/connection.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"

#include "source/common/common/empty_string.h"
#include "source/common/common/logger.h"
#include "source/common/network/raw_buffer_socket.h"
#include "source/common/network/transport_socket_options_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/tls/ssl_socket.h"

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "cilium/api/tls_wrapper.pb.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/network_policy.h"
#include "filter_state_cilium_policy.h"

namespace Envoy {
namespace Cilium {

namespace {

constexpr absl::string_view NotReadyReason{"Socket is not ready"};

// This SslSocketWrapper wraps a real SslSocket and hooks it up with
// TLS configuration derived from Cilium Network Policy.
class SslSocketWrapper : public Network::TransportSocket, Logger::Loggable<Logger::Id::connection> {
public:
  SslSocketWrapper(Extensions::TransportSockets::Tls::InitialState state,
                   const Network::TransportSocketOptionsConstSharedPtr& transport_socket_options)
      : state_(state), transport_socket_options_(transport_socket_options) {}

  // Network::TransportSocket
  void setTransportSocketCallbacks(Network::TransportSocketCallbacks& callbacks) override {
    callbacks_ = &callbacks;
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
    // Get the Cilium policy filter state from the callbacks in order to get the TLS
    // configuration.
    // Cilium socket option is only created if the (initial) policy for the local pod exists.
    // If the policy requires TLS then a TLS socket is used, but if the policy does not require
    // TLS a raw socket is used instead.
    auto& conn = callbacks_->connection();

    ENVOY_CONN_LOG(trace, "retrieving policy filter state", conn);
    auto policy_fs =
        conn.streamInfo().filterState()->getDataReadOnly<Cilium::CiliumPolicyFilterState>(
            Cilium::CiliumPolicyFilterState::key());

    if (policy_fs) {
      const auto& policy = policy_fs->getPolicy();

      // Resolve the destination security ID and port
      uint32_t destination_identity = 0;
      uint32_t destination_port = policy_fs->port_;
      const Network::Address::Ip* dip = nullptr;
      bool is_client = state_ == Extensions::TransportSockets::Tls::InitialState::Client;

      if (!policy_fs->ingress_) {
        Network::Address::InstanceConstSharedPtr dst_address =
            is_client ? callbacks_->connection().connectionInfoProvider().remoteAddress()
                      : callbacks_->connection().connectionInfoProvider().localAddress();
        if (dst_address) {
          dip = dst_address->ip();
          if (dip) {
            destination_port = dip->port();
            destination_identity = policy_fs->resolvePolicyId(dip);
          } else {
            ENVOY_CONN_LOG(warn, "cilium.tls_wrapper: Non-IP destination address: {}", conn,
                           dst_address->asString());
          }
        } else {
          ENVOY_CONN_LOG(warn, "cilium.tls_wrapper: No destination address", conn);
        }
      }

      // get the requested server name from the connection, if any
      const auto& sni = policy_fs->sni_;

      auto remote_id = policy_fs->ingress_ ? policy_fs->source_identity_ : destination_identity;
      auto port_policy = policy.findPortPolicy(policy_fs->ingress_, destination_port);
      const Envoy::Ssl::ContextConfig* config = nullptr;
      bool raw_socket_allowed = false;
      auto proxy_id = policy_fs->proxy_id_;
      Envoy::Ssl::ContextSharedPtr ctx =
          is_client ? port_policy.getClientTlsContext(proxy_id, remote_id, sni, &config,
                                                      raw_socket_allowed)
                    : port_policy.getServerTlsContext(proxy_id, remote_id, sni, &config,
                                                      raw_socket_allowed);
      if (ctx) {
        // create the underlying SslSocket
        auto status_or_socket = Extensions::TransportSockets::Tls::SslSocket::create(
            std::move(ctx), state_, transport_socket_options_, config->createHandshaker());
        if (status_or_socket.ok()) {
          socket_ = std::move(status_or_socket.value());
          // Set the callbacks
          socket_->setTransportSocketCallbacks(*callbacks_);
          // explicitly configure ssl connection with the latest configuration from the SSL socket.
          callbacks_->connection().connectionInfoSetter().setSslConnection(socket_->ssl());
        } else {
          ENVOY_CONN_LOG(error, "Unable to create ssl socket {}", conn,
                         status_or_socket.status().message());
        }
      } else if (config == nullptr && raw_socket_allowed) {
        // Use RawBufferSocket when policy allows without TLS.
        // If policy has TLS context config then a raw socket must NOT be used.
        socket_ = std::make_unique<Network::RawBufferSocket>();
        // Set the callbacks
        socket_->setTransportSocketCallbacks(*callbacks_);
      } else {
        policy.tlsWrapperMissingPolicyInc();

        std::string ip_str("<none>");
        if (policy_fs->ingress_) {
          Network::Address::InstanceConstSharedPtr src_address =
              is_client ? callbacks_->connection().connectionInfoProvider().localAddress()
                        : callbacks_->connection().connectionInfoProvider().remoteAddress();
          if (src_address) {
            const auto sip = src_address->ip();
            if (sip) {
              ip_str = sip->addressAsString();
            }
          }
        } else {
          if (dip) {
            ip_str = dip->addressAsString();
          }
        }
        ENVOY_CONN_LOG(
            warn,
            "cilium.tls_wrapper: Could not get {} TLS context for pod {} on {} IP {} (id {}) port "
            "{} sni \"{}\" and raw socket is not allowed",
            conn, is_client ? "client" : "server", policy_fs->pod_ip_,
            policy_fs->ingress_ ? "source" : "destination", ip_str, remote_id, destination_port,
            sni);
      }
    } else {
      ENVOY_CONN_LOG(warn,
                     "cilium.tls_wrapper: Can not correlate connection with Cilium Network "
                     "Policy (Cilium socket option not found)",
                     conn);
    }

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
  Network::TransportSocketCallbacks* callbacks_{};
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
