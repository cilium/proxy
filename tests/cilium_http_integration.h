#pragma once

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/pure.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"

#include "test/integration/http_integration.h"
#include "test/test_common/utility.h"

#include "absl/types/optional.h"
#include "cilium/api/accesslog.pb.h"
#include "google/protobuf/repeated_ptr_field.h"
#include "tests/accesslog_server.h"

namespace Envoy {

class CiliumHttpIntegrationTest : public HttpIntegrationTest,
                                  public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumHttpIntegrationTest(const std::string& config);
  ~CiliumHttpIntegrationTest();

  void createEnvoy() override;

  void initialize() override {
    accessLogServer_.clear();
    HttpIntegrationTest::initialize();
  }

  virtual std::string testPolicyFmt() PURE;

  virtual std::vector<std::pair<std::string, std::string>> testSecrets() {
    return std::vector<std::pair<std::string, std::string>>{};
  }

  absl::optional<::cilium::LogEntry>
  waitForAccessLogMessage(::cilium::EntryType entry_type,
                          std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    return accessLogServer_.waitForMessage(entry_type, timeout);
  }

  template <typename P> bool expectAccessLogRequestTo(P&& pred) {
    return accessLogServer_.expectRequestTo(pred);
  }

  template <typename P> bool expectAccessLogResponseTo(P&& pred) {
    return accessLogServer_.expectResponseTo(pred);
  }

  template <typename P> bool expectAccessLogDeniedTo(P&& pred) {
    return accessLogServer_.expectDeniedTo(pred);
  }

  static absl::optional<std::string>
  getHeader(const Protobuf::RepeatedPtrField<::cilium::KeyValue>& headers,
            const std::string& name) {
    for (const auto& entry : headers) {
      if (Http::LowerCaseString(entry.key()) == Http::LowerCaseString(name))
        return entry.value();
    }
    return absl::nullopt;
  }

  static bool hasHeader(const Protobuf::RepeatedPtrField<::cilium::KeyValue>& headers,
                        const std::string& name, const std::string& value = "") {
    for (const auto& entry : headers) {
      if (Http::LowerCaseString(entry.key()) == Http::LowerCaseString(name) &&
          (value == "" || entry.value() == value))
        return true;
    }
    return false;
  }

  AccessLogServer accessLogServer_;
};

} // namespace Envoy
