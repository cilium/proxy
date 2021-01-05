#pragma once

#include "test/integration/integration.h"

#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumTcpIntegrationTest : public BaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config);

  virtual std::string testPolicy();

  void initialize() override;
  void TearDown() override;

  AccessLogServer accessLogServer_;
};

}
