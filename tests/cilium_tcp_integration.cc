#include "tests/cilium_tcp_integration.h"

#include "envoy/network/address.h"

#include "test/test_common/environment.h"

#include "tests/bpf_metadata.h"

namespace Envoy {

const std::string TCP_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
)EOF";

CiliumTcpIntegrationTest::CiliumTcpIntegrationTest(const std::string& config)
    : BaseIntegrationTest(GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
  enableHalfClose(true);
#if 1
  for (Logger::Logger& logger : Logger::Registry::loggers()) {
    logger.setLevel(spdlog::level::trace);
  }
#endif
}

std::string CiliumTcpIntegrationTest::testPolicyFmt() {
  return TestEnvironment::substitute(TCP_POLICY_fmt, GetParam());
}

void CiliumTcpIntegrationTest::createEnvoy() {
  // fake upstreams have been created by now, use the port from the 1st upstream
  // in policy.
  auto port = fake_upstreams_[0]->localAddress()->ip()->port();
  policy_config = fmt::format(fmt::runtime(testPolicyFmt()), port);
  // Pass the fake upstream address to the cilium bpf filter that will set it as
  // an "original destination address".
  if (GetParam() == Network::Address::IpVersion::v4) {
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  } else {
    original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  }
  BaseIntegrationTest::createEnvoy();
}

void CiliumTcpIntegrationTest::initialize() {
  config_helper_.renameListener("tcp_proxy");
  BaseIntegrationTest::initialize();
}

} // namespace Envoy
