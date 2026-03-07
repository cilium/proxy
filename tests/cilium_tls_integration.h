#pragma once

#include <string>

#include "envoy/api/api.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context_manager.h"

#include "test/mocks/server/server_factory_context.h"

namespace Envoy {
namespace Cilium {

Network::UpstreamTransportSocketFactoryPtr
createClientSslTransportSocketFactory(Ssl::ContextManager& context_manager, Api::Api& api);

// Shared helper for creating a fake upstream TLS context.
// Used by both TCP and HTTP TLS integration tests.
Network::DownstreamTransportSocketFactoryPtr createUpstreamSslContext(
    const std::string& upstream_cert_name,
    NiceMock<Server::Configuration::MockTransportSocketFactoryContext>& factory_context,
    Ssl::ContextManager& context_manager);

} // namespace Cilium
} // namespace Envoy
