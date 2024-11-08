#pragma once

#include "envoy/registry/registry.h"
#include "envoy/server/transport_socket_config.h"

namespace Envoy {
namespace Cilium {

/**
 * Config registration for the Cilium TLS wrapper transport socket factory.
 * @see TransportSocketConfigFactory.
 */
class TlsWrapperConfigFactory : public virtual Server::Configuration::TransportSocketConfigFactory {
public:
  ~TlsWrapperConfigFactory() override = default;
  std::string name() const override { return name_; }

  const std::string name_ = "cilium.tls_wrapper";
};

class UpstreamTlsWrapperFactory
    : public Server::Configuration::UpstreamTransportSocketConfigFactory,
      public TlsWrapperConfigFactory {
public:
  Network::UpstreamTransportSocketFactoryPtr createTransportSocketFactory(
      const Protobuf::Message& config,
      Server::Configuration::TransportSocketFactoryContext& context) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(UpstreamTlsWrapperFactory);

class DownstreamTlsWrapperFactory
    : public Server::Configuration::DownstreamTransportSocketConfigFactory,
      public TlsWrapperConfigFactory {
public:
  Network::DownstreamTransportSocketFactoryPtr
  createTransportSocketFactory(const Protobuf::Message& config,
                               Server::Configuration::TransportSocketFactoryContext& context,
                               const std::vector<std::string>& server_names) override;
  ProtobufTypes::MessagePtr createEmptyConfigProto() override;
};

DECLARE_FACTORY(DownstreamTlsWrapperFactory);
} // namespace Cilium
} // namespace Envoy
