#include "source/common/config/decoded_resource_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/thread_local/thread_local_impl.h"

#include "tests/bpf_metadata.h" // host_map_config, original_dst_address
#include "tests/cilium_http_integration.h"

using namespace std::literals;

namespace Envoy {

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
          access_log_path: "{{ test_udsdir }}/access_log.sock"
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

  void Denied(Http::TestRequestHeaderMapImpl&& headers) {
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
  Denied({{":method", "GET"}, {":path", "/"}, {":authority", "host"}});
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

  auto clientConn = codec_client_->connection();

  // Create websocket framed data & write it on the client connection
  Buffer::OwnedImpl buf{"\x82\x5"
                        "hello"};
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

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
  buf.add("\x82\x6"
          "hello2"
          "\x82\x7"
          "hello21"
          "\x82\x3"
          "foo");
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

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
  absl::string_view frame16{"\x82\x7e\0\x5"
                            "len16",
                            9};
  buf.add(frame16);
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

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
  absl::string_view frame64{"\x82\x7f\0\0\0\0\0\0\0\x5"
                            "len64",
                            15};
  buf.add(frame64);
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

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
  buf.add("\x82\x5"
          "hello"
          "\x82\xe"
          "gap ");
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 9, &data));
  ASSERT_EQ(data.substr(seen_data_len), "hellogap ");
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write("bar42"));

  ASSERT_EQ(buf.length(), 0);
  buf.add("in between"
          "\x82\x3"
          "foo");
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 13, &data));
  ASSERT_EQ(data.substr(seen_data_len), "in betweenfoo");
  seen_data_len = data.length();

  response->waitForBodyData(7);
  resp = response->body();
  ASSERT_EQ(resp.substr(0, 7), "\x82\x5"
                               "bar42");
  response->clearBody();

  // Masked frames
  ASSERT_EQ(buf.length(), 0);
  auto msg = "heello there\r\n"s;
  unsigned char mask[4] = {0x12, 0x34, 0x56, 0x78};
  auto masked = msg;
  for (size_t i = 0; i < msg.length(); i++) {
    masked[i] = msg[i] ^ mask[i % 4];
  }
  buf.add("\x82\x8e");
  buf.add(mask, 4);
  buf.add(masked.data(), masked.length());
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

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

  // 2nd masked frame
  ASSERT_EQ(buf.length(), 0);
  auto msg2 = "hello there\r\n"s;
  unsigned char mask2[4] = {0x90, 0xab, 0xcd, 0xef};
  auto masked2 = msg2;
  for (size_t i = 0; i < msg2.length(); i++) {
    masked2[i] = msg2[i] ^ mask2[i % 4];
  }
  // Write frame header
  buf.add("\x82\x8d");
  buf.add(mask2, 4);
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  // Write 5 first bytes
  buf.add(masked2.data(), 5);
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), absl::string_view(msg2.data(), 5));
  seen_data_len = data.length();

  // Write remaining bytes
  buf.add(masked2.data() + 5, masked2.length() - 5);
  clientConn->write(buf, false);
  // Run the dispatcher so that the write event is handled
  clientConn->dispatcher().run(Event::Dispatcher::RunType::NonBlock);

  ASSERT_TRUE(fake_upstream_connection->waitForData(seen_data_len + 13 - 5, &data));
  ASSERT_EQ(data.substr(seen_data_len), msg2.data() + 5);
  seen_data_len = data.length();

  ASSERT_TRUE(fake_upstream_connection->write(msg2));

  response->waitForBodyData(15);
  resp = response->body();

  ASSERT_EQ(resp.substr(0, 15), "\x82\xd"
                                "hello there\r\n");
  response->clearBody();

  // Close
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Wait for websocket close frame
  response->waitForBodyData(2);
  absl::string_view close_frame{"\x88\0", 2};
  ASSERT_EQ(response->body(), close_frame);

  cleanupUpstreamAndDownstream();
}

} // namespace Envoy
