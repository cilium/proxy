#pragma once

#include "test/integration/http_integration.h"
#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumHttpIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
 public:
  CiliumHttpIntegrationTest(const std::string& config);
  ~CiliumHttpIntegrationTest();

  /**
   * Initializer for an individual integration test.
   */
  void initialize() override;

  AccessLogServer accessLogServer_;
};

}  // namespace Envoy
