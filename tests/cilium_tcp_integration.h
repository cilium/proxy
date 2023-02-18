#pragma once

#include "test/integration/integration.h"

#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumTcpIntegrationTest : public BaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config);

  void createEnvoy() override;

  virtual std::string testPolicyFmt();

  void initialize() override;
  void TearDown() override;

  AccessLogServer accessLogServer_;
};

} // namespace Envoy
