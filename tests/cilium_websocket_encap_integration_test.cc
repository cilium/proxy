#include "test/integration/integration.h"
#include "test/integration/utility.h"
#include "test/test_common/environment.h"

#include "cilium/websocket_protocol.h"
#include "tests/bpf_metadata.h" // original_dst_address
#include "tests/cilium_tcp_integration.h"

using namespace std::literals;

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
    stat_prefix: listener_0
    name: listener_0
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
      - name: cilium.network.websocket.client
        typed_config:
          "@type": type.googleapis.com/cilium.WebSocketClient
          access_log_path: "{{ test_udsdir }}/access_log.sock"
          version: "13"
          path: "/"
          origin: "jarno.cilium.rocks"
          host: "jarno.cilium.rocks"
          key: "super-secret-key"
          handshake_timeout:
            seconds: 5
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
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
            "true")) {}
  size_t unmaskData(void* void_frame, size_t len, uint8_t opcode = OPCODE_BIN) {
    uint8_t* frame = reinterpret_cast<uint8_t*>(void_frame);
    if (frame[0] != (0x80 | opcode)) {
      return 0;
    }
    size_t frame_offset = 2;
    uint64_t data_len = frame[1] & ~0x80;
    switch (data_len) {
    case 126:
      data_len = (frame[2] << 8) + frame[3];
      frame_offset += sizeof(uint16_t);
      break;
    case 127:
      data_len = 0;
      for (size_t i = 0; i < sizeof(uint64_t); i++) {
        data_len <<= 8;
        data_len += frame[frame_offset + i];
      }
      frame_offset += sizeof(uint64_t);
      break;
    }
    char mask[4];
    bool masked = frame[1] & 0x80;
    if (masked) {
      memcpy(mask, frame + frame_offset, sizeof(mask)); // NOLINT(safe-memcpy)
      frame_offset += sizeof(mask);
    }
    if (data_len != len - frame_offset) {
      return 0;
    }

    if (masked) {
      int mask_offset = 0;
      for (size_t i = frame_offset; i < len; i++) {
        frame[i] ^= mask[mask_offset++];
        if (mask_offset == sizeof(mask)) {
          mask_offset = 0;
        }
      }
    }
    return frame_offset;
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumWebSocketIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

#define X_REQUEST_ID_HEADER "x-request-id"
#define HEADER_SEPARATOR ": "
#define X_REQUEST_ID_VALUE "12345678-abcd-1234-5678-1234567890ab"

#define CRLF "\r\n"
static const char EXPECTED_HANDSHAKE_FMT[] =
    "GET / HTTP/1.1" CRLF "host: jarno.cilium.rocks" CRLF "upgrade: websocket" CRLF
    "connection: upgrade" CRLF "sec-websocket-key: c3VwZXItc2VjcmV0LWtleQ==" CRLF
    "sec-websocket-version: 13" CRLF "origin: jarno.cilium.rocks" CRLF
    "x-envoy-original-dst-host: {}" CRLF X_REQUEST_ID_HEADER HEADER_SEPARATOR X_REQUEST_ID_VALUE
        CRLF "content-length: 0" CRLF CRLF;

namespace {

size_t normalize_x_request_id(std::string& headers) {
  auto idx = headers.find(X_REQUEST_ID_HEADER HEADER_SEPARATOR);
  if (idx != std::string::npos) {
    idx += sizeof(X_REQUEST_ID_HEADER HEADER_SEPARATOR) - 1; // w/o the \0 in the end
    auto lf = headers.find(CRLF, idx);
    if (lf != std::string::npos) {
      // replace
      headers.replace(idx, lf - idx, X_REQUEST_ID_VALUE);
      return lf - idx;
    }
  }
  return 0;
}

} // namespace

// Test Websocket handshake with missing handshake response
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketHandshakeNonHTTPResponse) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection,
                                                       std::chrono::milliseconds(1000000)));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_handshake;

  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(),
                                                    &received_handshake, std::chrono::seconds(10)));
  ASSERT_EQ(normalize_x_request_id(received_handshake), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_handshake, expected_handshake);
  ASSERT_TRUE(fake_upstream_connection->write("\x82\x5"
                                              "world"));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();
  tcp_client->close();

  test_server_->waitForCounterGe("websocket.handshake_not_http", 1);
}

static const char HANDSHAKE_RESPONSE_FMT[] =
    "HTTP/1.1 101 Switching Protocols" CRLF "Upgrade: websocket" CRLF "Connection: Upgrade" CRLF
    "Sec-WebSocket-Accept: {}" CRLF CRLF;

// Test Websocket handshake with invalid accept key hash.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketHandshakeInvalidResponse) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with invalid hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "invalid-hash");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  test_server_->waitForCounterGe("websocket.handshake_invalid_websocket_response", 1);

  tcp_client->waitForHalfClose();
  tcp_client->close();
}

// Test successful handshake where client writes data first, right after connection has been
// created.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketHandshakeSuccess) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  // check we get the hello in a websocket binary data frame
  ASSERT_TRUE(
      fake_upstream_connection->waitForData(expected_handshake.length() + 11, &received_data));
  received_data.erase(0, expected_handshake.length()); // strip handshake
  // unmask the payload
  auto frame_offset = unmaskData(received_data.data(), received_data.size());
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(received_data.substr(frame_offset, 5), "hello");

  ASSERT_TRUE(fake_upstream_connection->write("\x82\x5"
                                              "world"));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();
  tcp_client->close();

  EXPECT_EQ("world", tcp_client->data());
}

// Test successful handshake where client does not send any data, and the server side sends data
// right after the handshake response.
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketHandshakeNoData) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  ASSERT_TRUE(fake_upstream_connection->write("\x82\x5"
                                              "world"));
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

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  ASSERT_TRUE(
      fake_upstream_connection->waitForData(expected_handshake.length() + 11, &received_data));
  received_data.erase(0, expected_handshake.length()); // strip handshake
  // unmask the payload
  auto frame_offset = unmaskData(received_data.data(), received_data.size());
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(received_data.substr(frame_offset, 5), "hello");

  ASSERT_TRUE(fake_upstream_connection->write("\x82\x5"
                                              "world"));
  tcp_client->waitForData("world");
  ASSERT_TRUE(tcp_client->write("hell2", true));
  // 11 bytes for encoded "hell2" and 6 bytes for websocket close due to end stream == true
  ASSERT_TRUE(
      fake_upstream_connection->waitForData(expected_handshake.length() + 28, &received_data));
  received_data.erase(0, expected_handshake.length() + 11); // strip handshake and 1st hello
  // unmask the payload
  frame_offset = unmaskData(received_data.data(), 11);
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(received_data.substr(frame_offset, 5), "hell2");
  // check for the close frame
  received_data.erase(0, 11); // strip 2nd hello
  frame_offset = unmaskData(received_data.data(), received_data.length(), OPCODE_CLOSE);
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(frame_offset, 6);

  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForDisconnect();
}

TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketLargeWrite) {
  config_helper_.setBufferLimits(1024, 1024);
  initialize();

  std::string data(1024 * 32, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write(data));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  // Data is split into 16k chunks, so there are 2 headers of 8 bytes each
  ASSERT_TRUE(fake_upstream_connection->waitForData(
      expected_handshake.length() + 2 * 8 + data.size(), &received_data));
  received_data.erase(0, expected_handshake.length()); // strip handshake
  // unmask the 1st frame
  auto frame_offset = unmaskData(received_data.data(), 8 + 16 * 1024);
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(received_data.substr(frame_offset, 16 * 1024), data.substr(0, 16 * 1024));
  received_data.erase(0, frame_offset + 16 * 1024); // strip 1st frame
  // unmask the 2nd frame
  frame_offset = unmaskData(received_data.data(), 8 + 16 * 1024);
  ASSERT_TRUE(frame_offset > 0);
  ASSERT_EQ(received_data.substr(frame_offset, 16 * 1024), data.substr(16 * 1024, 16 * 1024));

  // writing data in one large chunk
  ASSERT_TRUE(fake_upstream_connection->write("\x82\x7e\x80\x00"s));
  ASSERT_TRUE(fake_upstream_connection->write(data));
  tcp_client->waitForData(data);
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
  EXPECT_EQ(downstream_pauses, downstream_resumes);
}

// Test that a downstream flush works correctly (all data is flushed)
TEST_P(CiliumWebSocketIntegrationTest, CiliumWebSocketDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size / 4, size / 4);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  tcp_client->readDisable(true);
  ASSERT_TRUE(tcp_client->write("", true));

  // This ensures that readDisable(true) has been run on it's thread
  // before tcp_client starts writing.
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  // writing data in one large chunk

  ASSERT_TRUE(fake_upstream_connection->write("\x82\x7f\x03\x20\0\0"s));
  ASSERT_TRUE(fake_upstream_connection->write(data, true));

  test_server_->waitForCounterGe("cluster.cluster1.upstream_flow_control_paused_reading_total", 1);
  EXPECT_EQ(test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
                ->value(),
            0);
  tcp_client->readDisable(false);
  tcp_client->waitForData(data);
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
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
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on
  // it's thread before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true, true, std::chrono::milliseconds(30000)));

  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  size_t min_size = expected_handshake.length() + data.size() + 14 + 6;
  ASSERT_TRUE(
      fake_upstream_connection->waitForData(FakeRawConnection::waitForAtLeastBytes(min_size)));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 0);
  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
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

  std::string expected_handshake =
      fmt::format(fmt::runtime(EXPECTED_HANDSHAKE_FMT), original_dst_address->asString());
  std::string received_data;
  ASSERT_TRUE(fake_upstream_connection->waitForData(expected_handshake.length(), &received_data));
  ASSERT_EQ(normalize_x_request_id(received_data), sizeof(X_REQUEST_ID_VALUE) - 1);
  ASSERT_EQ(received_data, expected_handshake);

  // Handshake response with the correct hash value
  std::string handshake_response =
      fmt::format(fmt::runtime(HANDSHAKE_RESPONSE_FMT), "GjgmQ9MzNsn3h7+vuIzY25rbQ9M=");
  ASSERT_TRUE(fake_upstream_connection->write(handshake_response));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on
  // it's thread before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  // test_server_->waitForCounterGe("tcp.tcp_stats.upstream_flush_total", 1);

  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}

} // namespace Envoy
