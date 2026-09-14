#include "tests/cilium_tls_integration.h"

#include <gmock/gmock-actions.h>
#include <gmock/gmock-spec-builders.h>

#include <string>
#include <utility>

#include "envoy/api/api.h"
#include "envoy/common/exception.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls.pb.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/stats/scope.h"

#include "source/common/tls/client_ssl_socket.h"
#include "source/common/tls/context_config_impl.h"

#include "test/mocks/server/admin.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

namespace Envoy {
namespace Cilium {

Network::UpstreamTransportSocketFactoryPtr
createClientSslTransportSocketFactory(Ssl::ContextManager& context_manager, Api::Api& api,
                                      Stats::Scope& stats_scope) {
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
  auto cfg_or_error = Extensions::TransportSockets::Tls::ClientContextConfigImpl::create(
      tls_context, mock_factory_ctx);
  // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
  THROW_IF_NOT_OK(cfg_or_error.status());
  auto cfg = std::move(cfg_or_error.value());
  // The TLS context interns its stat names in the symbol table of the factory context owned by
  // 'context_manager', so 'stats_scope' must share that symbol table (e.g. be the server factory
  // context scope of the test) rather than an isolated store with its own symbol table.
  auto factory_or_error = Extensions::TransportSockets::Tls::ClientSslSocketFactory::create(
      std::move(cfg), context_manager, stats_scope);
  // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
  THROW_IF_NOT_OK(factory_or_error.status());
  return std::move(factory_or_error.value());
}

} // namespace Cilium
} // namespace Envoy
