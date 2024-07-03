#include "tests/cilium_tls_integration.h"

#include "envoy/api/api.h"
#include "envoy/network/transport_socket.h"

#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/ssl_socket.h"

#include "test/integration/server.h"
#include "test/mocks/server/transport_socket_factory_context.h"
#include "test/test_common/environment.h"

#include "gtest/gtest.h"

namespace Envoy {
namespace Cilium {

Network::UpstreamTransportSocketFactoryPtr
createClientSslTransportSocketFactory(Ssl::ContextManager& context_manager, Api::Api& api) {
  std::string yaml_plain = R"EOF(
  common_tls_context:
    validation_context:
      trusted_ca:
        filename: "{{ test_rundir }}/test/config/integration/certs/cacert.pem"
)EOF";

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(yaml_plain), tls_context);

  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> mock_factory_ctx;
  ON_CALL(mock_factory_ctx.server_context_, api()).WillByDefault(testing::ReturnRef(api));
  auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ClientContextConfigImpl>(
      tls_context, mock_factory_ctx);
  static auto* client_stats_store = new Stats::TestIsolatedStoreImpl();
  return Network::UpstreamTransportSocketFactoryPtr{
      new Extensions::TransportSockets::Tls::ClientSslSocketFactory(
          std::move(cfg), context_manager, *client_stats_store->rootScope())};
}

} // namespace Cilium
} // namespace Envoy
