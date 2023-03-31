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

  void initialize() override {
    accessLogServer_.clear();
    HttpIntegrationTest::initialize();
  }

  virtual std::string testPolicyFmt() PURE;

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
    absl::optional<std::string> ret;
    for (const auto& entry : headers) {
      if (entry.key() == name)
        ret = entry.value();
    }
    return ret;
  }

  static bool hasHeader(const Protobuf::RepeatedPtrField<::cilium::KeyValue>& headers,
                        const std::string& name, const std::string& value = "") {
    for (const auto& entry : headers) {
      if (entry.key() == name && entry.value() == value)
        return true;
    }
    return false;
  }

  AccessLogServer accessLogServer_;
};

} // namespace Envoy
