#include "tests/cilium_http_integration.h"

#include "envoy/network/address.h"

#include "source/common/common/logger.h"

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

CiliumHttpIntegrationTest::~CiliumHttpIntegrationTest() {}

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
