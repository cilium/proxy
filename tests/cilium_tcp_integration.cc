#include "envoy/network/address.h"

#include "test/test_common/environment.h"

#include "tests/bpf_metadata.h"
#include "tests/cilium_tcp_integration.h"

namespace Envoy {

const std::string TCP_POLICY = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
)EOF";

CiliumTcpIntegrationTest::CiliumTcpIntegrationTest(const std::string& config)
  : BaseIntegrationTest(GetParam(), config),
    accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
  enable_half_close_ = true;
}

std::string CiliumTcpIntegrationTest::testPolicy() {
  return TestEnvironment::substitute(TCP_POLICY, GetParam());
}

void CiliumTcpIntegrationTest::initialize() {
  policy_config = testPolicy();
  config_helper_.renameListener("tcp_proxy");
  BaseIntegrationTest::initialize();
  // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
  if (GetParam() == Network::Address::IpVersion::v4) {
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
  } else {
    original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
  }
}

void CiliumTcpIntegrationTest::TearDown() {
  npmap.reset();
}

}
