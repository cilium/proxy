#pragma once

#include "envoy/api/api.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context_manager.h"

namespace Envoy {
namespace Cilium {

Network::UpstreamTransportSocketFactoryPtr
createClientSslTransportSocketFactory(Ssl::ContextManager& context_manager, Api::Api& api);

} // namespace Cilium
} // namespace Envoy
