#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sstream>
#include <string>

#include "envoy/network/address.h"

#include "test/integration/base_integration_test.h"

#include "absl/strings/string_view.h"

namespace Envoy {

inline testing::AssertionResult
ciliumTcpResponseMatches(const char* actual_expression, const char* /* matcher_expression */,
                         absl::string_view actual,
                         const testing::Matcher<absl::string_view>& matcher) {
  testing::StringMatchResultListener listener;
  if (matcher.MatchAndExplain(actual, &listener)) {
    return testing::AssertionSuccess();
  }

  std::ostringstream expected;
  matcher.DescribeTo(&expected);

  testing::AssertionResult failure = testing::AssertionFailure();
  failure << "Value of: " << actual_expression << "\nExpected: " << expected.str()
          << "\n  Actual: " << testing::PrintToString(actual);
  if (!listener.str().empty()) {
    failure << "\n" << listener.str();
  }
  return failure;
}

// Wait for a matching TCP response and stop the test if it does not arrive. This uses the
// Matcher<absl::string_view> directly instead of passing tcp_client->data() to ASSERT_THAT.
// ASSERT_THAT would adapt the matcher to Matcher<const std::string&>, causing clang-tidy's static
// analyzer to incorrectly report the GoogleMock adapter allocation as
// clang-analyzer-cplusplus.NewDeleteLeaks in gmock-matchers.h.
#define CILIUM_ASSERT_TCP_RESPONSE(tcp_client, matcher)                                            \
  do {                                                                                             \
    const testing::Matcher<absl::string_view> response_matcher = (matcher);                        \
    (tcp_client)->waitForTcpResponse(response_matcher, TestUtility::DefaultTimeout);               \
    ASSERT_PRED_FORMAT2(::Envoy::ciliumTcpResponseMatches, (tcp_client)->data(),                   \
                        response_matcher);                                                         \
  } while (false)

class CiliumTcpIntegrationTest : public BaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config);

  void createEnvoy() override;

  virtual std::string testPolicyFmt();

  void initialize() override;
};

} // namespace Envoy
