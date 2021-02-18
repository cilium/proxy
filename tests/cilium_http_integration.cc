#include "tests/cilium_http_integration.h"

#include "common/common/logger.h"
#include "envoy/network/address.h"
#include "tests/bpf_metadata.h"

namespace Envoy {

CiliumHttpIntegrationTest::CiliumHttpIntegrationTest(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), config),
      accessLogServer_(
          TestEnvironment::unixDomainSocketPath("access_log.sock")) {
#if 0
  for (Logger::Logger& logger : Logger::Registry::loggers()) {
    logger.setLevel(spdlog::level::trace);
  }
#endif
}

CiliumHttpIntegrationTest::~CiliumHttpIntegrationTest() {}

void CiliumHttpIntegrationTest::initialize() {
  HttpIntegrationTest::initialize();
  // Pass the fake upstream address to the cilium bpf filter that will set it as
  // an "original destination address".
  if (GetParam() == Network::Address::IpVersion::v4) {
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(
        Network::Test::getLoopbackAddressString(GetParam()),
        fake_upstreams_.back()->localAddress()->ip()->port());
  } else {
    original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(
        Network::Test::getLoopbackAddressString(GetParam()),
        fake_upstreams_.back()->localAddress()->ip()->port());
  }
}

}  // namespace Envoy
