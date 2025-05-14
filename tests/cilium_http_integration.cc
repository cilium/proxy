#include "tests/cilium_http_integration.h"

#include <fmt/base.h>
#include <fmt/format.h>
#include <spdlog/common.h>

#include <memory>
#include <string>

#include "envoy/http/codec.h" // IWYU pragma: keep
#include "envoy/network/address.h"

#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/http/codec_client.h"
#include "source/common/network/address_impl.h"

#include "test/integration/http_integration.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"

#include "tests/bpf_metadata.h"

namespace Envoy {

CiliumHttpIntegrationTest::CiliumHttpIntegrationTest(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
#if 1
  for (Logger::Logger& logger : Logger::Registry::loggers()) {
    logger.setLevel(spdlog::level::trace);
  }
#endif
}

CiliumHttpIntegrationTest::~CiliumHttpIntegrationTest() = default;

void CiliumHttpIntegrationTest::createEnvoy() {
  // fake upstreams have been created by now, use the port from the 1st upstream
  // in policy.
  auto port = fake_upstreams_[0]->localAddress()->ip()->port();
  policy_config = fmt::format(fmt::runtime(testPolicyFmt()), port);
  sds_configs = testSecrets();
  // Pass the fake upstream address to the cilium bpf filter that will set it as
  // an "original destination address".
  if (GetParam() == Network::Address::IpVersion::v4) {
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  } else {
    original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  }
  HttpIntegrationTest::createEnvoy();
}

} // namespace Envoy
