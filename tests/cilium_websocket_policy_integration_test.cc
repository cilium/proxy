#include <fmt/base.h>
#include <fmt/format.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <string>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"

#include "test/integration/fake_upstream.h"
#include "test/integration/integration_tcp_client.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "tests/cilium_tcp_integration.h"

namespace Envoy {

//
// Cilium filters with TCP proxy
//

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
    connect_timeout: 5s
    type: STATIC
    load_assignment:
      cluster_name: internal-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 0
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
  - name: internal-cluster
    connect_timeout: 5s
    type: STATIC
    load_assignment:
      cluster_name: internal-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 11111
  - name: internal-cluster2
    connect_timeout: 5s
    type: STATIC
    load_assignment:
      cluster_name: internal-cluster
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 22222
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    filter_chains:
      filters:
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
          cluster: internal-cluster
  - name: internal-listener
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 11111
    listener_filters:
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
    filter_chains:
    - filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          upgrade_configs:
          - upgrade_type: websocket
          codec_type: auto
          use_remote_address: true
          skip_xff_append: true
          http_filters:
          - name: test_l7policy
            typed_config:
              "@type": type.googleapis.com/cilium.L7Policy
              access_log_path: "{{ test_udsdir }}/access_log.sock"
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: policy_enabled
            virtual_hosts:
              name: integration
              domains: "*"
              routes:
              - route:
                  cluster: internal-cluster2
                  max_grpc_timeout:
                    seconds: 0
                    nanos: 0
                match:
                  prefix: "/"
  - name: internal-listener2
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 22222
    filter_chains:
    - filters:
      - name: cilium.network.websocket.server
        typed_config:
          "@type": type.googleapis.com/cilium.WebSocketServer
          access_log_path: "{{ test_udsdir }}/access_log.sock"
          origin: "jarno.cilium.rocks"
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumWebSocketIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumWebSocketIntegrationTest()
      : CiliumTcpIntegrationTest(fmt::format(
            fmt::runtime(TestEnvironment::substitute(cilium_tcp_proxy_config_fmt, GetParam())),
            "true")) {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // replace 0 port in "cluster1" with the fake backend port
      bootstrap.mutable_static_resources()
          ->mutable_clusters(0)
          ->mutable_load_assignment()
          ->mutable_endpoints(0)
          ->mutable_lb_endpoints(0)
          ->mutable_endpoint()
          ->mutable_address()
          ->mutable_socket_address()
          ->set_port_value(fake_upstreams_[0]->localAddress()->ip()->port());
    });
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
  tcp_client->waitForData("hello");

  ASSERT_TRUE(tcp_client->write("hello"));
  std::string received;
  ASSERT_TRUE(fake_upstream_connection->waitForData(5, &received));
  ASSERT_EQ(received, "hello");

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
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
  tcp_client->waitForData("world");

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  ASSERT_TRUE(tcp_client->write("hello", true));
  ASSERT_TRUE(fake_upstream_connection->waitForData(10, &received));
  ASSERT_EQ(received, "hellohello");
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForDisconnect();
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
  tcp_client->waitForData(data);

  test_server_->waitForCounterGe("websocket.ping_sent_count", 1);

  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_EQ(upstream_pauses, upstream_resumes);
  uint32_t downstream_pauses =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_paused_reading_total")->value();
  uint32_t downstream_resumes =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_resumed_reading_total")->value();
  // Since we are receiving early data, downstream connection will already be read
  // disabled so downstream pause metric is not emitted when upstream buffer hits high
  // watermark. When the upstream buffer watermark goes down, downstream will be read
  // enabled and downstream resume metric will be emitted.
  EXPECT_EQ(downstream_pauses, 2);
  EXPECT_EQ(downstream_resumes, 2);
}

} // namespace Envoy
