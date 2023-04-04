#pragma once

#include "test/integration/integration.h"

#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumBaseIntegrationTest : public BaseIntegrationTest {
public:
  CiliumBaseIntegrationTest(Network::Address::IpVersion version, const std::string& config);

  void createEnvoy() override;

  virtual std::string testPolicyFmt();

  void initialize() override;

  Network::Address::IpVersion version_;
  AccessLogServer accessLogServer_;
};

class CiliumTcpIntegrationTest : public CiliumBaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config)
      : CiliumBaseIntegrationTest(GetParam(), config) {}
  void TearDown() override;
};

} // namespace Envoy
