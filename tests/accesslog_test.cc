#include <memory>

#include "envoy/http/protocol.h"

#include "source/common/network/address_impl.h"

#include "test/mocks/network/connection.h"
#include "test/mocks/upstream/cluster_info.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/utility.h"

#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Cilium {

class CiliumTest : public testing::Test {
protected:
  Event::SimulatedTimeSystem time_system_;
};

TEST_F(CiliumTest, AccessLog) {
  Http::TestRequestHeaderMapImpl headers{{":method", "GET"},
                                         {":path", "/"},
                                         {":authority", "host"},
                                         {"x-forwarded-proto", "http"},
                                         {"x-request-id", "ba41267c-cfc2-4a92-ad3e-cd084ab099b4"}};
  Network::MockConnection connection;
  auto source_address = std::make_shared<Network::Address::Ipv4Instance>("5.6.7.8", 45678);
  auto destination_address = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 80);
  connection.stream_info_.protocol_ = Http::Protocol::Http11;
  connection.stream_info_.start_time_ = time_system_.systemTime();
  connection.stream_info_.downstream_connection_info_provider_->setRemoteAddress(source_address);
  connection.stream_info_.downstream_connection_info_provider_->setLocalAddress(
      destination_address);

  AccessLog::Entry log;

  log.initFromRequest("1.2.3.4", 42, true, 1, source_address, 173, destination_address,
                      connection.stream_info_, headers);

  EXPECT_EQ(log.entry_.is_ingress(), true);
  EXPECT_EQ(log.entry_.proxy_id(), 42);
  EXPECT_EQ(log.entry_.entry_type(), ::cilium::EntryType::Request);
  EXPECT_NE(log.entry_.timestamp(), 0);
  EXPECT_STREQ(log.entry_.policy_name().c_str(), "1.2.3.4");
  EXPECT_STREQ("1.2.3.4:80", log.entry_.destination_address().c_str());
  EXPECT_STREQ("5.6.7.8:45678", log.entry_.source_address().c_str());
  EXPECT_EQ(1, log.entry_.source_security_id());
  EXPECT_EQ(173, log.entry_.destination_security_id());

  EXPECT_EQ(log.entry_.has_http(), true);
  EXPECT_EQ(::cilium::HttpProtocol::HTTP11, log.entry_.http().http_protocol());
  EXPECT_STREQ("/", log.entry_.http().path().c_str());
  EXPECT_STREQ("GET", log.entry_.http().method().c_str());
  EXPECT_STREQ("host", log.entry_.http().host().c_str());
  EXPECT_STREQ("http", log.entry_.http().scheme().c_str());

  // Request headers not captured above
  EXPECT_EQ(log.entry_.http().headers_size(), 1);
  EXPECT_STREQ(log.entry_.http().headers(0).key().c_str(), "x-request-id");
  EXPECT_STREQ(log.entry_.http().headers(0).value().c_str(),
               "ba41267c-cfc2-4a92-ad3e-cd084ab099b4");

  Http::TestResponseHeaderMapImpl response_headers{{"my-response-header", "response"}};

  NiceMock<Event::SimulatedTimeSystem> time_source;
  log.updateFromResponse(response_headers, time_source);

  // Unmodified
  EXPECT_EQ(log.entry_.has_http(), true);
  EXPECT_EQ(::cilium::HttpProtocol::HTTP11, log.entry_.http().http_protocol());
  EXPECT_STREQ("/", log.entry_.http().path().c_str());
  EXPECT_STREQ("GET", log.entry_.http().method().c_str());
  EXPECT_STREQ("host", log.entry_.http().host().c_str());
  EXPECT_STREQ("http", log.entry_.http().scheme().c_str());

  // x-request-id and response headers only
  EXPECT_EQ(log.entry_.http().headers_size(), 2);
  EXPECT_STREQ(log.entry_.http().headers(0).key().c_str(), "x-request-id");
  EXPECT_STREQ(log.entry_.http().headers(0).value().c_str(),
               "ba41267c-cfc2-4a92-ad3e-cd084ab099b4");
  EXPECT_STREQ(log.entry_.http().headers(1).key().c_str(), "my-response-header");
  EXPECT_STREQ(log.entry_.http().headers(1).value().c_str(), "response");
}

} // namespace Cilium
} // namespace Envoy
