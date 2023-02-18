#pragma once

#include "test/integration/http_integration.h"

#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumHttpIntegrationTest : public HttpIntegrationTest,
                                  public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumHttpIntegrationTest(const std::string& config);
  ~CiliumHttpIntegrationTest();

  void createEnvoy() override;

  virtual std::string testPolicyFmt() PURE;

  AccessLogServer accessLogServer_;
};

} // namespace Envoy
