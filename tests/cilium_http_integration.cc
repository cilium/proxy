#include "tests/cilium_http_integration.h"

#include <fmt/base.h>
#include <fmt/format.h>
#include <spdlog/common.h>

#include <memory>
#include <string>

#include "envoy/http/codec.h" // IWYU pragma: keep
#include "envoy/network/address.h"

#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/http/codec_client.h"
#include "source/common/network/address_impl.h"

#include "test/integration/http_integration.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"

#include "tests/bpf_metadata.h"

namespace Envoy {

CiliumHttpIntegrationTest::CiliumHttpIntegrationTest(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
#if 1
  for (Logger::Logger& logger : Logger::Registry::loggers()) {
    logger.setLevel(spdlog::level::trace);
  }
#endif
}

CiliumHttpIntegrationTest::~CiliumHttpIntegrationTest() = default;

void CiliumHttpIntegrationTest::denied(Http::TestRequestHeaderMapImpl&& headers) {
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(response->waitForEndStream());

  // Validate that request access log message with x-request-id is logged
  absl::optional<std::string> maybe_x_request_id;
  EXPECT_TRUE(expectAccessLogDeniedTo([&maybe_x_request_id](const ::cilium::LogEntry& entry) {
    maybe_x_request_id = getHeader(entry.http().headers(), "x-request-id");
    return entry.http().status() == 0;
  }));
  ASSERT_TRUE(maybe_x_request_id.has_value());

  // Validate that response x-request-id is the same as in request
  absl::optional<std::string> maybe_x_request_id_resp;
  EXPECT_TRUE(
      expectAccessLogResponseTo([&maybe_x_request_id_resp](const ::cilium::LogEntry& entry) {
        maybe_x_request_id_resp = getHeader(entry.http().headers(), "x-request-id");
        return entry.http().status() == 403;
      }));
  ASSERT_TRUE(maybe_x_request_id_resp.has_value());
  EXPECT_EQ(maybe_x_request_id.value(), maybe_x_request_id_resp.value());

  EXPECT_TRUE(response->complete());
  EXPECT_EQ("403", response->headers().getStatusValue());
  cleanupUpstreamAndDownstream();
}

void CiliumHttpIntegrationTest::deniedL3(Http::TestRequestHeaderMapImpl&& headers) {
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  ASSERT_TRUE(codec_client_->waitForDisconnect());

  // Validate that request access log message is logged
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry&) { return true; }));
  cleanupUpstreamAndDownstream();
}

void CiliumHttpIntegrationTest::accepted(Http::TestRequestHeaderMapImpl&& headers) {
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

  // Validate that request access log message with x-request-id is logged
  absl::optional<std::string> maybe_x_request_id;
  EXPECT_TRUE(expectAccessLogRequestTo([&maybe_x_request_id](const ::cilium::LogEntry& entry) {
    maybe_x_request_id = getHeader(entry.http().headers(), "x-request-id");
    return entry.http().status() == 0;
  }));
  ASSERT_TRUE(maybe_x_request_id.has_value());

  // Validate that response x-request-id is the same as in request
  absl::optional<std::string> maybe_x_request_id_resp;
  EXPECT_TRUE(
      expectAccessLogResponseTo([&maybe_x_request_id_resp](const ::cilium::LogEntry& entry) {
        maybe_x_request_id_resp = getHeader(entry.http().headers(), "x-request-id");
        return entry.http().status() == 200;
      }));
  ASSERT_TRUE(maybe_x_request_id_resp.has_value());
  EXPECT_EQ(maybe_x_request_id.value(), maybe_x_request_id_resp.value());

  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());
  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_EQ(0, upstream_request_->bodyLength());
  cleanupUpstreamAndDownstream();
}

void CiliumHttpIntegrationTest::createEnvoy() {
  // fake upstreams have been created by now, use the port from the 1st upstream
  // in policy.
  auto port = fake_upstreams_[0]->localAddress()->ip()->port();
  policy_config = fmt::format(fmt::runtime(testPolicyFmt()), port);
  sds_configs = testSecrets();
  // Pass the fake upstream address to the cilium bpf filter that will set it as
  // an "original destination address".
  if (GetParam() == Network::Address::IpVersion::v4) {
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  } else {
    original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(
        Network::Test::getLoopbackAddressString(GetParam()), port);
  }
  HttpIntegrationTest::createEnvoy();
}

} // namespace Envoy
