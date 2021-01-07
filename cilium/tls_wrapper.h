#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

namespace Envoy {
namespace Cilium {

// clang-format off
#define ALL_SSL_SOCKET_FACTORY_STATS(COUNTER)                                 \
  COUNTER(ssl_context_update_by_sds)                                          \
  COUNTER(upstream_context_secrets_not_ready)                                 \
  COUNTER(downstream_context_secrets_not_ready)
// clang-format on

/**
 * Wrapper struct for SSL socket factory stats. @see stats_macros.h
 */
struct SslSocketFactoryStats {
  ALL_SSL_SOCKET_FACTORY_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Config registration for the Cilium TLS wrapper transport socket factory.
 * @see TransportSocketConfigFactory.
 */
class TlsWrapperConfigFactory
    : public virtual Server::Configuration::TransportSocketConfigFactory {
 public:
  ~TlsWrapperConfigFactory() override = default;
  std::string name() const override { return name_; }

  const std::string name_ = "cilium.tls_wrapper";
};

class UpstreamTlsWrapperFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory,
      public TlsWrapperConfigFactory {
 public:
  Network::TransportSocketFactoryPtr createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(UpstreamTlsWrapperFactory);

class DownstreamTlsWrapperFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public TlsWrapperConfigFactory {
 public:
  Network::TransportSocketFactoryPtr createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context,
      const std::vector<std::string>& server_names) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(DownstreamTlsWrapperFactory);
}  // namespace Cilium
}  // namespace Envoy
