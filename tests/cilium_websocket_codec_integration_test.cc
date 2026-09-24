#include <fmt/base.h>
#include <fmt/format.h>
#include <gmock/gmock.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <utility>

#include "envoy/common/platform.h"
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/network/socket.h"

#include "test/integration/fake_upstream.h"
#include "test/integration/integration_tcp_client.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/utility.h"

#include "tests/cilium_tcp_integration.h"

namespace Envoy {

//
// Cilium filters with TCP proxy
//

// params: is_ingress ("true", "false"), WebSocket server listener port
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
  - name: websocket-server
    connect_timeout: 5s
    type: STATIC
    load_assignment:
      cluster_name: websocket-server
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: "{{ ip_loopback_address }}"
                port_value: {1}
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
  - name: listener_0
    address:
      socket_address:
        address: "{{ ip_loopback_address }}"
        port_value: 0
    listener_filters:
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: cilium.network.websocket.client
        typed_config:
          "@type": type.googleapis.com/cilium.WebSocketClient
          access_log_path: "{{ test_udsdir }}/access_log.sock"
          origin: "jarno.cilium.rocks"
          host: "jarno.cilium.rocks"
          ping_interval:
            nanos: 1000000
          ping_when_idle: true
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: websocket-server
  - name: websocket-server
    address:
      socket_address:
        address: "{{ ip_loopback_address }}"
        port_value: {1}
    filter_chains:
      filters:
      - name: cilium.network.websocket.server
        typed_config:
          "@type": type.googleapis.com/cilium.WebSocketServer
          access_log_path: "{{ test_udsdir }}/access_log.sock"
          origin: "jarno.cilium.rocks"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: websocket_server_tcp_stats
          cluster: cluster1
)EOF";

class CiliumWebSocketIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumWebSocketIntegrationTest()
      : CiliumWebSocketIntegrationTest(reserveWebSocketServerPort(GetParam())) {}

  void initialize() override {
    CiliumTcpIntegrationTest::initialize();
    reserved_websocket_server_port_.release();
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

private:
  struct ReservedWebSocketServerPort {
    ReservedWebSocketServerPort(uint32_t port, Network::SocketPtr socket)
        : port_(port), socket_(std::move(socket)) {}

    void release() { socket_.reset(); }

    const uint32_t port_;
    Network::SocketPtr socket_;
  };

  static ReservedWebSocketServerPort
  reserveWebSocketServerPort(Network::Address::IpVersion version) {
    auto reserved =
        Network::Test::bindFreeLoopbackPort(version, Network::Socket::Type::Stream, true);
    return {reserved.first->ip()->port(), std::move(reserved.second)};
  }

  static std::string makeConfig(Network::Address::IpVersion version,
                                const ReservedWebSocketServerPort& reserved_port) {
    return fmt::format(
        fmt::runtime(TestEnvironment::substitute(cilium_tcp_proxy_config_fmt, version)), "true",
        reserved_port.port_);
  }

  explicit CiliumWebSocketIntegrationTest(ReservedWebSocketServerPort reserved_port)
      : CiliumTcpIntegrationTest(makeConfig(GetParam(), reserved_port)),
        reserved_websocket_server_port_(std::move(reserved_port)) {}

  ReservedWebSocketServerPort reserved_websocket_server_port_;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumWebSocketIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Test upstream writing before downstream downstream does.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(fake_upstream_connection->write("hello"));
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::StartsWith("hello"));

  ASSERT_TRUE(tcp_client->write("hello"));
  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &received));
  ASSERT_EQ(received, "hello");

  // A FIN in one direction must not prevent data from flowing in the reverse direction. The first
  // CLOSE crosses both WebSocket codecs and becomes a half-close at the TCP client.
  ASSERT_TRUE(fake_upstream_connection->write("upstream final", true));
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::Eq("helloupstream final"));
  tcp_client->waitForHalfClose();

  // The first CLOSE is only a directional FIN. Keepalive PING/PONG processing must continue while
  // the reverse direction remains open.
  const uint64_t ping_count = test_server_->counter("websocket.ping_sent_count")->value();
  test_server_->waitForCounterGe("websocket.ping_sent_count", ping_count + 1);

  // The TCP client can still send after receiving that FIN. Its own FIN produces the CLOSE response
  // only after the reverse-direction data has crossed the tunnel.
  ASSERT_TRUE(tcp_client->write("downstream final", true));
  ASSERT_TRUE(fake_upstream_connection->waitForData(5 + sizeof("downstream final") - 1, &received));
  ASSERT_EQ(received, "hellodownstream final");
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

// Test proxying data in both directions, and that all data is flushed properly
// when there is an upstream disconnect.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketUpstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &received));
  ASSERT_EQ(received, "hello");

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(fake_upstream_connection->write("world"));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();
  tcp_client->close();

  EXPECT_EQ("world", tcp_client->data());
}

#if ENVOY_PLATFORM_ENABLE_SEND_RST
// A TCP reset is an abort, not a directional FIN, and must tear down the tunnel immediately.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketUpstreamReset) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->close(Network::ConnectionCloseType::AbortReset));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForDisconnect();
}

#endif

// Test proxying data in both directions, and that all data is flushed properly
// when the client disconnects.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketDownstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &received));
  ASSERT_EQ(received, "hello");
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::StartsWith("world"));

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(tcp_client->write("hello", true));
  ASSERT_TRUE(fake_upstream_connection->waitForData(10, &received));
  ASSERT_EQ(received, "hellohello");
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  const uint64_t ping_count = test_server_->counter("websocket.ping_sent_count")->value();
  test_server_->waitForCounterGe("websocket.ping_sent_count", ping_count + 1);

  ASSERT_TRUE(fake_upstream_connection->write("upstream final", true));
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::Eq("worldupstream final"));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForDisconnect();
}

// A real close of the source TCP socket still arrives at Envoy as a FIN. Verify that the FIN is
// carried through the WebSocket tunnel as CLOSE, while final data in the reverse direction is
// decoded and written to the source-side downstream socket before the CLOSE response completes
// the connection teardown.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketDownstreamCloseReceivesFinalData) {
  initialize();
  const uint64_t ping_count = test_server_->counter("websocket.ping_sent_count")->value();

  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;

  // The server-side WebSocket filter stops iteration until it has accepted the handshake and
  // restored x-envoy-original-dst-host. Reaching the ORIGINAL_DST upstream proves that happened.
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &received));
  ASSERT_EQ(received, "hello");

  // The client starts its PING timer only after validating the server's 101 response.
  test_server_->waitForCounterGe("websocket.ping_sent_count", ping_count + 1);
  EXPECT_EQ(test_server_->counter("websocket.handshake_invalid_websocket_request")->value(), 0);
  EXPECT_EQ(test_server_->counter("websocket.handshake_invalid_websocket_response")->value(), 0);

  auto downstream_tx = test_server_->counter("tcp.tcp_stats.downstream_cx_tx_bytes_total");
  ASSERT_NE(downstream_tx, nullptr);
  const uint64_t downstream_tx_before = downstream_tx->value();
  auto protocol_errors = test_server_->counter("websocket.protocol_error");
  ASSERT_NE(protocol_errors, nullptr);
  const uint64_t protocol_errors_before = protocol_errors->value();

  // Close the client socket completely, rather than merely half-closing it with write(..., true).
  // Envoy observes the orderly TCP FIN and carries it through the tunnel as WebSocket CLOSE.
  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  const std::string final_data = "upstream final";
  ASSERT_TRUE(fake_upstream_connection->write(final_data, true));

  // The closed IntegrationTcpClient can no longer observe received data. The TCP proxy byte
  // counter verifies that the decoded final data was written to the source-side downstream socket.
  test_server_->waitForCounterGe("tcp.tcp_stats.downstream_cx_tx_bytes_total",
                                 downstream_tx_before + final_data.size());
  EXPECT_EQ(downstream_tx->value(), downstream_tx_before + final_data.size());

  // The upstream FIN completes the delayed WebSocket CLOSE response, after which both TCP proxy
  // connections close normally without treating transport termination as a protocol error.
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  EXPECT_EQ(protocol_errors->value(), protocol_errors_before);
}

TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketLargeWrite) {
  config_helper_.setBufferLimits(1024, 1024);
  initialize();

  std::string data(1024 * 16, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write(data));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size(), &received));
  ASSERT_EQ(received, data);
  ASSERT_TRUE(fake_upstream_connection->write(data));
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::StartsWith(data));

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.websocket-server.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.websocket-server.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_EQ(upstream_pauses, upstream_resumes);
  uint32_t downstream_pauses =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_paused_reading_total")->value();
  uint32_t downstream_resumes =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_resumed_reading_total")->value();
  // Early data usually has downstream reads disabled before the upstream buffer hits high
  // watermark, which suppresses the downstream pause metric. If scheduling lets the pause
  // happen first, it must still be balanced by the resume below.
  EXPECT_TRUE(downstream_pauses == 0 || downstream_pauses == downstream_resumes)
      << "downstream pauses: " << downstream_pauses
      << ", downstream resumes: " << downstream_resumes;
  EXPECT_EQ(downstream_resumes, 1);
}

// Test that a downstream flush works correctly (all data is flushed)
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size / 4, size / 4);
  enableHalfClose(true);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  tcp_client->readDisable(true);
  ASSERT_TRUE(tcp_client->write("", true));

  // Confirm that the downstream FIN crossed the WebSocket tunnel before sending a large response.
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  ASSERT_TRUE(fake_upstream_connection->write(data, true));

  test_server_->waitForCounterGe(
      "cluster.websocket-server.upstream_flow_control_paused_reading_total", 1);
  EXPECT_EQ(
      test_server_->counter("cluster.websocket-server.upstream_flow_control_resumed_reading_total")
          ->value(),
      0);
  tcp_client->readDisable(false);
  CILIUM_ASSERT_TCP_RESPONSE(tcp_client, testing::Eq(data));
  tcp_client->waitForHalfClose();

  uint32_t upstream_pauses =
      test_server_->counter("cluster.websocket-server.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.websocket-server.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_GE(upstream_pauses, upstream_resumes);
  EXPECT_GT(upstream_resumes, 0);
}

// Test that an upstream flush works correctly (all data is flushed)
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketUpstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  enableHalfClose(true);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // Confirm that the upstream FIN crossed the WebSocket tunnel before sending a large request.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true, true, std::chrono::milliseconds(30000)));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);

  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size(), &received));
  ASSERT_EQ(received, data);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 0);
}

// Test that Envoy doesn't crash or assert when shutting down with an upstream
// flush active
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketUpstreamFlushEnvoyExit) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Confirm that the WebSocket handshake and keepalive timer are active.
  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // Confirm that the upstream FIN crossed the WebSocket tunnel before filling the write buffer.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}

} // namespace Envoy
