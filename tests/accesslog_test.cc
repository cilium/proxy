#include "cilium/accesslog.h"

#include "cilium/socket_option.h"
#include "common/network/address_impl.h"
#include "envoy/http/protocol.h"
#include "envoy/network/socket.h"
#include "gtest/gtest.h"
#include "test/mocks/network/connection.h"
#include "test/mocks/stream_info/mocks.h"
#include "test/test_common/utility.h"

namespace Envoy {
namespace Cilium {

class CiliumTest : public testing::Test {
 protected:
  Event::SimulatedTimeSystem time_system_;
  Network::Address::InstanceConstSharedPtr local_address_;
  Network::Address::InstanceConstSharedPtr remote_address_;
};

TEST_F(CiliumTest, AccessLog) {
  Http::TestRequestHeaderMapImpl headers{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"x-forwarded-proto", "http"},
      {"x-request-id", "ba41267c-cfc2-4a92-ad3e-cd084ab099b4"}};
  NiceMock<StreamInfo::MockStreamInfo> stream_info;
  stream_info.protocol_ = Http::Protocol::Http11;
  stream_info.start_time_ = time_system_.systemTime();
  Network::MockConnection connection;
  Network::Socket::OptionsSharedPtr options =
      std::make_shared<Network::Socket::Options>();
  options->push_back(std::make_shared<Cilium::SocketOption>(
      nullptr, 1, 173, true, 80, "1.2.3.4", nullptr));
  local_address_ =
      std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 80);
  remote_address_ =
      std::make_shared<Network::Address::Ipv4Instance>("5.6.7.8", 45678);

  ENVOY_LOG_MISC(error, "source_address: {}", remote_address_->asString());
  ENVOY_LOG_MISC(error, "destination_address: {}", local_address_->asString());

  EXPECT_CALL(connection, socketOptions())
      .WillOnce(testing::ReturnRef(options));
  EXPECT_CALL(connection, localAddress())
      .WillRepeatedly(testing::ReturnRef(local_address_));
  EXPECT_CALL(connection, remoteAddress())
      .WillRepeatedly(testing::ReturnRef(remote_address_));

  AccessLog::Entry log;

  log.InitFromRequest("1.2.3.4", true, &connection, headers, stream_info);

  EXPECT_EQ(log.entry_.is_ingress(), true);
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

  EXPECT_EQ(log.entry_.http().headers_size(), 1);
  EXPECT_STREQ(log.entry_.http().headers(0).key().c_str(), "x-request-id");
  EXPECT_STREQ(log.entry_.http().headers(0).value().c_str(),
               "ba41267c-cfc2-4a92-ad3e-cd084ab099b4");
}

}  // namespace Cilium
}  // namespace Envoy
