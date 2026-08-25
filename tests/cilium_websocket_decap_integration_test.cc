#include <fmt/base.h>
#include <fmt/format.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "envoy/event/dispatcher.h"

#include "source/common/buffer/buffer_impl.h"

#include "test/integration/fake_upstream.h"
#include "test/integration/integration_stream_decoder.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "absl/strings/string_view.h"
#include "tests/bpf_metadata.h" // host_map_config, original_dst_address
#include "tests/cilium_http_integration.h"

using namespace std::literals;

namespace Envoy {

namespace {

enum class PayloadLengthEncoding { Minimal, Uint16, Uint64 };

std::string maskedClientFrame(absl::string_view payload,
                              PayloadLengthEncoding encoding = PayloadLengthEncoding::Minimal) {
  constexpr std::array<uint8_t, 4> mask = {0x12, 0x34, 0x56, 0x78};
  std::string frame;
  frame.reserve(14 + payload.size());
  frame.push_back('\x82'); // FIN and binary opcode

  if (encoding == PayloadLengthEncoding::Minimal && payload.size() < 126) {
    frame.push_back(static_cast<char>(0x80 | payload.size()));
  } else if (encoding == PayloadLengthEncoding::Uint16 ||
             (encoding == PayloadLengthEncoding::Minimal && payload.size() <= UINT16_MAX)) {
    frame.push_back(static_cast<char>(0x80 | 126));
    frame.push_back(static_cast<char>(payload.size() >> 8));
    frame.push_back(static_cast<char>(payload.size()));
  } else {
    frame.push_back(static_cast<char>(0x80 | 127));
    for (int shift = 56; shift >= 0; shift -= 8) {
      frame.push_back(static_cast<char>(payload.size() >> shift));
    }
  }

  for (uint8_t byte : mask) {
    frame.push_back(static_cast<char>(byte));
  }
  for (size_t i = 0; i < payload.size(); ++i) {
    frame.push_back(static_cast<char>(static_cast<uint8_t>(payload[i]) ^ mask[i % mask.size()]));
  }
  return frame;
}

} // namespace

// params: is_ingress ("true", "false")
const std::string cilium_tcp_proxy_config_fmt = R"EOF(
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: cluster1
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    connect_timeout:
      seconds: 1
  - name: xds-grpc-cilium
    connect_timeout:
      seconds: 5
    type: STATIC
    lb_policy: ROUND_ROBIN
    http2_protocol_options:
    load_assignment:
      cluster_name: xds-grpc-cilium
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              pipe:
                path: /var/run/cilium/xds.sock
  listeners:
    name: http
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    listener_filters:
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network.websocket.server
        typed_config:
          "@type": type.googleapis.com/cilium.WebSocketServer
          origin: "jarno.cilium.rocks"
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumWebSocketIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumWebSocketIntegrationTest()
      : CiliumHttpIntegrationTest(fmt::format(
            fmt::runtime(TestEnvironment::substitute(cilium_tcp_proxy_config_fmt, GetParam())),
            "false")) {
    host_map_config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::/104" ]
)EOF";
  }

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 42
  policy: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
)EOF",
                                       GetParam());
  }

  void denied(Http::TestRequestHeaderMapImpl&& headers) {
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("403", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumWebSocketIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumWebSocketIntegrationTest, DeniedNonWebSocket) {
  initialize();
  denied({{":method", "GET"}, {":path", "/"}, {":authority", "host"}});
}

TEST_P(CiliumWebSocketIntegrationTest, AcceptedWebSocket) {
  initialize();
  auto request_headers = Http::TestRequestHeaderMapImpl{
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"Upgrade", "websocket"},
      {"Connection", "Upgrade"},
      {"Origin", "jarno.cilium.rocks"},
      {"Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="},
      {"Sec-WebSocket-Version", "13"},
      {"x-request-id", "000000ff-0000-0000-0000-000000000001"},
      {"x-envoy-original-dst-host", original_dst_address->asString()}};
  codec_client_ = makeHttpConnection(lookupPort("http"));

  IntegrationStreamDecoderPtr response = codec_client_->makeHeaderOnlyRequest(request_headers);
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  // Wait for the response to be read by the codec client.
  response->waitForHeaders();
  EXPECT_EQ("101", response->headers().getStatusValue());

  auto client_conn = codec_client_->connection();

  // Create masked WebSocket framed data and write it on the client connection.
  Buffer::OwnedImpl buf{maskedClientFrame("hello")};
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  std::string data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &data));
  ASSERT_EQ(data, "hello");
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  // There is no way to clear the fake upstream data, so we must keep track of how much of it
  // we already saw.
  auto seen_data_len = data.length();

  response->waitForBodyData(7);
  absl::string_view resp = response->body();
  ASSERT_EQ(resp.substr(0, 7), "\x82\x5"
                               "world");
  response->clearBody();

  // Send multiple frames back-to-back
  ASSERT_EQ(buf.length(), 0);
  buf.add(maskedClientFrame("hello2"));
  buf.add(maskedClientFrame("hello21"));
  buf.add(maskedClientFrame("foo"));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 16, &data));
  ASSERT_EQ(data.substr(seen_data_len), "hello2hello21foo");
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write("bar"));

  response->waitForBodyData(5);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 5), "\x82\x3"
                               "bar");
  response->clearBody();

  // Bigger size formats & multiple responses.
  // Officially optimal length formats must be used, but our implementation
  // accepts larger formats with less data, which makes testing easier.
  ASSERT_EQ(buf.length(), 0);
  const std::string frame16 = maskedClientFrame("len16", PayloadLengthEncoding::Uint16);
  buf.add(frame16);
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), "len16");
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write("foo"));
  response->waitForBodyData(5);
  ASSERT_TRUE(fake_upstream_connection->write("bar"));
  response->waitForBodyData(10);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 5), "\x82\x3"
                               "foo");
  ASSERT_EQ(resp.substr(5, 5), "\x82\x3"
                               "bar");
  response->clearBody();

  // 64-bit size format
  // Officially optimal length formats must be used, but our implementation
  // accepts larger formats with less data, which makes testing easier.
  ASSERT_EQ(buf.length(), 0);
  const std::string frame64 = maskedClientFrame("len64", PayloadLengthEncoding::Uint64);
  buf.add(frame64);
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), "len64");
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write("hello"));
  response->waitForBodyData(7);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 7), "\x82\x5"
                               "hello");
  response->clearBody();

  // Gaps within a frame
  ASSERT_EQ(buf.length(), 0);
  const std::string hello_frame = maskedClientFrame("hello");
  const std::string gap_frame = maskedClientFrame("gap in between");
  buf.add(hello_frame);
  // Send the second frame's header, masking key, and first four payload bytes.
  buf.add(gap_frame.substr(0, 10));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 9, &data));
  ASSERT_EQ(data.substr(seen_data_len), "hellogap ");
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write("bar42"));

  ASSERT_EQ(buf.length(), 0);
  buf.add(gap_frame.substr(10));
  buf.add(maskedClientFrame("foo"));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 13, &data));
  ASSERT_EQ(data.substr(seen_data_len), "in betweenfoo");
  seen_data_len = data.length();

  response->waitForBodyData(7);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 7), "\x82\x5"
                               "bar42");
  response->clearBody();

  // Masked frame
  ASSERT_EQ(buf.length(), 0);
  auto msg = "heello there\r\n"s;
  buf.add(maskedClientFrame(msg));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 14, &data));
  ASSERT_EQ(data.substr(seen_data_len), msg);
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write(msg));

  response->waitForBodyData(16);
  ASSERT_EQ(response->body().length(), 16);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 16), "\x82\xe"
                                "heello there\r\n");
  response->clearBody();

  // Split masked frame
  ASSERT_EQ(buf.length(), 0);
  auto msg2 = "hello there\r\n"s;
  const std::string masked2 = maskedClientFrame(msg2);
  // Write the frame header and masking key.
  buf.add(masked2.substr(0, 6));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  // Write 5 first bytes
  buf.add(masked2.substr(6, 5));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), absl::string_view(msg2.data(), 5));
  seen_data_len = data.length();

  // Write remaining bytes
  buf.add(masked2.substr(11));
  client_conn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  client_conn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 13 - 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), msg2.data() + 5);
  // seen_data_len = data.length(); // not used after, no need to update

  ASSERT_TRUE(fake_upstream_connection->write(msg2));

  response->waitForBodyData(15);
  resp = response->body();

  ASSERT_EQ(resp.substr(0, 15), "\x82\xd"
                                "hello there\r\n");
  response->clearBody();

  // Close
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Wait for websocket close frame, has to be exactly 2 bytes
  response->waitForBodyData(2);
  absl::string_view close_frame{"\x88\0", 2};
  ASSERT_EQ(response->body(), close_frame);
  codec_client_->close();
}

} // namespace Envoy
