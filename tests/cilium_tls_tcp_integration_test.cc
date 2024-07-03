#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/ssl_socket.h"

#include "test/integration/ssl_utility.h"

#include "tests/cilium_tcp_integration.h"
#include "tests/cilium_tls_integration.h"

using testing::AtLeast;

namespace Envoy {
namespace Cilium {

//
// Cilium filters with TCP proxy & Upstream TLS
//

// params: is_ingress ("true", "false")
const std::string cilium_tls_tcp_proxy_config_fmt = R"EOF(
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: tls-cluster
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    connect_timeout:
      seconds: 1
    transport_socket:
      name: "cilium.tls_wrapper"
      typed_config:
        "@type": type.googleapis.com/cilium.UpstreamTlsWrapperContext
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
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    listener_filters:
    - name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
    filter_chains:
    - filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: tls-cluster
)EOF";

class CiliumTLSIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumTLSIntegrationTest(const std::string& config) : CiliumTcpIntegrationTest(config) {
#if 0
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
#endif
  }

  void initialize() override {
    CiliumTcpIntegrationTest::initialize();

    payload_reader_.reset(new WaitForPayloadReader(*dispatcher_));
  }

  void createUpstreams() override {
    if (upstream_tls_) {
      auto config = upstreamConfig();
      config.upstream_protocol_ = FakeHttpConnection::Type::HTTP1;
      config.enable_half_close_ = true;
      fake_upstreams_.emplace_back(
          new FakeUpstream(createUpstreamSslContext(), 0, version_, config));
    } else {
      CiliumTcpIntegrationTest::createUpstreams(); // maybe BaseIntegrationTest::createUpstreams()
    }
  }

  // TODO(mattklein123): This logic is duplicated in various places. Cleanup in
  // a follow up.
  Network::DownstreamTransportSocketFactoryPtr createUpstreamSslContext() {
    envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext tls_context;
    auto* common_tls_context = tls_context.mutable_common_tls_context();
    auto* tls_cert = common_tls_context->add_tls_certificates();
    tls_cert->mutable_certificate_chain()->set_filename(TestEnvironment::runfilesPath(
        fmt::format("test/config/integration/certs/{}cert.pem", upstream_cert_name_)));
    tls_cert->mutable_private_key()->set_filename(TestEnvironment::runfilesPath(
        fmt::format("test/config/integration/certs/{}key.pem", upstream_cert_name_)));

    auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static auto* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store->rootScope(),
        std::vector<std::string>{});
  }

  void setupConnections() {
    initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the mock buffer factory so the newly created SSL client will have
    // a mock write buffer. This allows us to track the bytes actually written
    // to the socket.

    EXPECT_CALL(*mock_buffer_factory_, createBuffer_(_, _, _))
        .Times(AtLeast(1))
        .WillOnce(Invoke([&](std::function<void()> below_low, std::function<void()> above_high,
                             std::function<void()> above_overflow) -> Buffer::Instance* {
          client_write_buffer_ =
              new NiceMock<MockWatermarkBuffer>(below_low, above_high, above_overflow);
          ON_CALL(*client_write_buffer_, move(_))
              .WillByDefault(Invoke(client_write_buffer_, &MockWatermarkBuffer::baseMove));
          ON_CALL(*client_write_buffer_, drain(_))
              .WillByDefault(Invoke(client_write_buffer_, &MockWatermarkBuffer::trackDrains));
          return client_write_buffer_;
        }));
    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("tcp_proxy"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    ssl_client_ = dispatcher_->createClientConnection(
        address, Network::Address::InstanceConstSharedPtr(),
        context_->createTransportSocket(nullptr, nullptr), nullptr, nullptr);

    // Perform the SSL handshake. Loopback is whitelisted in tcp_proxy.json for
    // the ssl_auth filter so there will be no pause waiting on auth data.
    ssl_client_->addConnectionCallbacks(connect_callbacks_);
    ssl_client_->enableHalfClose(true);
    ssl_client_->addReadFilter(payload_reader_);
    ssl_client_->connect();
    while (!connect_callbacks_.connected()) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }
  }

  // Test proxying data in both directions with envoy doing TCP and TLS
  // termination.
  void sendAndReceiveTlsData(const std::string& data_to_send_upstream,
                             const std::string& data_to_send_downstream) {
    FakeRawConnectionPtr fake_upstream_connection;
    AssertionResult result = fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
    RELEASE_ASSERT(result, result.message());

    // Ship some data upstream.
    Buffer::OwnedImpl buffer(data_to_send_upstream);
    ssl_client_->write(buffer, false);
    while (client_write_buffer_->bytesDrained() != data_to_send_upstream.size()) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }

    // Make sure the data makes it upstream.
    ASSERT_TRUE(fake_upstream_connection->waitForData(data_to_send_upstream.size()));

    // Now send data downstream and make sure it arrives.
    ASSERT_TRUE(fake_upstream_connection->write(data_to_send_downstream));
    payload_reader_->setDataToWaitFor(data_to_send_downstream);
    ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);

    // Clean up.
    Buffer::OwnedImpl empty_buffer;
    ssl_client_->write(empty_buffer, true);
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
    ASSERT_TRUE(fake_upstream_connection->write("", true));
    ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
    ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);
    EXPECT_TRUE(payload_reader_->readLastByte());
    EXPECT_TRUE(connect_callbacks_.closed());
  }

  // Upstream
  bool upstream_tls_{true};
  std::string upstream_cert_name_{"upstreamlocalhost"};

  // Downstream
  std::shared_ptr<WaitForPayloadReader> payload_reader_;
  MockWatermarkBuffer* client_write_buffer_;
  Network::UpstreamTransportSocketFactoryPtr context_;
  Network::ClientConnectionPtr ssl_client_;
  ConnectionStatusCallbacks connect_callbacks_;
};

// upstream_tls_context tructed_ca from test/config/integration/certs/upstreamcacert.pem
// downstream_tls_context certificate_chain from test/config/integration/certs/servercert.pem
// downstream_tls_context private_key from test/config/integration/certs/serverkey.pem
const std::string TCP_POLICY_UPSTREAM_TLS_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      upstream_tls_context:
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUfXpfjZAzA9sFKKe0k9M1rCGG9rwwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjQwNDA4MTA0\nMjUzWhcNMjYwNDA4MTA0MjUzWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQ5VS5O8LtJdNY7\nL9sqH6vVhr9wyHsb7bvBSmg9JAxTU8vSFG/Uj4zoJDBYtEivU9F7leeqcqVLU9MA\n2vvYt/LS7/j2HOU0AfilbIGRJiho24AMlrkgXQSweVD+Y46hH42xythcZhwYS6JQ\nMpe0jkSk8SDUZTCCFeosbt8yTxOILgNsFUgUJ1pkUFyQQDSW+cYfruXgg/U/BdP2\nbme/E6Wf41KhZIZJTGzbxmgRrmF29ktOSwLyJcKpMCVNFforIBOKnF7ANKirnAS4\nFuBx6Q4peQ6/qwmXcucBD4X+YBoTi6+CZejW9LHcZX4gFjWKFlny4QJKxz2eFS+1\neudq86kCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFHrsizu33Ld1ed/tUUow717Z5RCDMB8GA1UdIwQYMBaAFHrsizu3\n3Ld1ed/tUUow717Z5RCDMA0GCSqGSIb3DQEBCwUAA4IBAQCPlwh6v03l09vHYA8k\nFX0YVZDUKOcz8wtoRHwkTjetGRaDF2xEu2NGr/RHFS5EyJ9kuwgc1nOGS8lfqDk9\nCznok/2qsN+ctp571ufhK+EZf5FI9etQJP1f0YleXrP3KR3ztQ5zLGXCv6E0oqXi\n6ct4FZJwq5RdP4LYJUWCfCAf5z8Yr6nLUlXTW2Kwwi3+3isqc97jdRMkL37Y3CyR\nEgAHSbw26XozFmY+K7ptspwb8zPaWKMUDNSGJVnfCqo8ABWJbDcdRa/AZA4KXScP\nH/A2sZtKx8b3mOIu/uX5NQCO+e0Tvm6qqCSGr+Ykcn7HI6Rr43d19He/zn82oHZF\nqhaf\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEhTCCA22gAwIBAgIUQRkh3sY/JN5+tu5NX3Tbyx0Y8l8wDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjQwNDA4MTA0MjUzWhcNMjYw\nNDA4MTA0MjUzWjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQCqoyXM9pY5gDpLVap5mr0NtQjqCvh+GXZyP7BP\nP2S+oNtSaLLAe5+yNDJoldZSplLGYwrWWJtjWJedeQ5JnhpbFVKrGXDIBtQ/6B/v\noKEkdh3BOB79IKhbmNQTA9pFV+xypvM+IWFr4p5bvjTRgncdXdlzEf6g5ECNdgdi\nhlpdL3aAY/Ko6cEWAzaxypJAumzsaw4HX1HiBP7rhHHZrLsIPc6MZ/LhKztIgJIO\n3U2VOE4uRbcf1uBEkE6H63PKGBnuHJ5qkmLS6IoF9sl7pvydLj5tp1FB8twQMxwP\nWGRTZkpQ121zH5aBIEL1C/1WHgZ6AROEKvMK408e9fiAEfPLAgMBAAGjgdkwgdYw\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMFoGA1UdEQRTMFGGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYYXaHR0cDovL2JhY2tlbmQubHlmdC5jb22CCGx5ZnQuY29tggx3d3cubHlm\ndC5jb20wHQYDVR0OBBYEFF+sq41Nw9S3XL1yJQ51PLCa+mwUMB8GA1UdIwQYMBaA\nFBn+c0Qg6qbDyfGRTNk1jzuKuSOAMA0GCSqGSIb3DQEBCwUAA4IBAQB56Z7/YUQ6\nSkazZPO2Eodg/4eKHQPEluzbz13/wkTBMTewgLgXRCVow8025yt0NaQ9AQzrKELc\nWBD+BuoTA8koD52zXmG9kjpIzajIqv2urWIaH1vUzfM26uJgiQKXX3eo24fbGRQi\nW452PvGPYoGAtucrEg15MrGlfqLMPkNIJ3ufIWRh+ycriWb8kHe+TgB6XQQGhHdJ\nD0+MXSOkPoNM7I8hU2PNl29krHTl3npYK0zG4AOF6tbOuu6bta94kV8PQ4YBfojF\no8vYmMboYDfZnnh+92WT4Ra/BSIm/NXilo3mXOu+cuRP6Kl3kpJPT0zZIjI5DBLn\nQmJKb8oDcA7+\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAqqMlzPaWOYA6S1WqeZq9DbUI6gr4fhl2cj+wTz9kvqDbUmiy\nwHufsjQyaJXWUqZSxmMK1libY1iXnXkOSZ4aWxVSqxlwyAbUP+gf76ChJHYdwTge\n/SCoW5jUEwPaRVfscqbzPiFha+KeW7400YJ3HV3ZcxH+oORAjXYHYoZaXS92gGPy\nqOnBFgM2scqSQLps7GsOB19R4gT+64Rx2ay7CD3OjGfy4Ss7SICSDt1NlThOLkW3\nH9bgRJBOh+tzyhgZ7hyeapJi0uiKBfbJe6b8nS4+badRQfLcEDMcD1hkU2ZKUNdt\ncx+WgSBC9Qv9Vh4GegEThCrzCuNPHvX4gBHzywIDAQABAoIBAQCpC+QBADGnWY9m\n3sF6o3+zuqvQIXo4gsVDPjFO8UC/UeC17Z9Y7aAyDV/7GKYxTzEl9SzhWProGvZp\nPWqYKBd4MNGrTBLdN1bC0RYCcaHy20lzCEQ7BUWFKQzAocp1dDt9AkRsQume1e2I\nehEdliCnaThptWQKxNXmzw1V4EBZm3Jf18azA82Op5O8uD8B7pLdM7cfXVfY5HIL\nN9HFY5yLJwM+N3M447StKQhfwohLtCuB8dVnYgVNKkqYfPyRSYT6h4OFJI+i1BRu\nyzEZoSVfa7oKAEStVH3G76M4TzKL5msU7AJrIogWFNYIy1jWEMJsCmhD5dbQhbJD\n9q1SgkIBAoGBAOJFaRl2PL7yf9RPh0E4iAJmqz9LxTk9PCa1Lu/EdtUdnqumPfVD\nfbsLxLUMYA5qQP411t+fFEgt2eBYj57WWhh035WhCpvhFhLgFqfXyFosI5Ku9xfE\nsOoCxzGOdCVfSi5PqL+cB49H6Msc5R0Wm1nr6Xz9vuW+U8AlxwdYSdNLAoGBAMEO\ngLej7FqBnnySXfTINFpXatPq4EaoMKqqI5Yjy0PlzBWbQtFV01zjo9xH9eCNRxrj\n1mz5tV3i1zyYapULL8hQ/qYVryf/sc4QGqEi2PPmk6KlR1729MMH83dWhuGgojyf\nkPy/+f5vqklRqQa90g01mea7O8mU10cUNmem85GBAoGBAMikiBfd8uvXmWaoxuUc\nve5zIDNWeyLQnAAu9doDOuSsCUFoftR37ovoWZu5x4vAyLUjBNDy/Ucr8WGw5loQ\n9X9uU70ZOpETPUGrmCtpeu4K6dhucgmPjtlTcVMOYQuqvdrnJFoUf9ecCl/h1YC/\nxS4ttbPyRk7vQNDILv7iWUSVAoGAK51xKwvXm+LowU/39hM88KQLOHE51fytcgEa\nJRNVGrPR1ZfMEqsHI1cyb9O6Es8YH1UV3mzTsrBK3B+7BI0QcHsL7M29UpYLv3gX\n7AuJZCDVfctFQokcZutm77EWq+a0gGm0QcXFXtwvZn0SaLl9uQpBCMWIDlSYBjDk\n0aoAIQECgYAfqxwy93/9Ib3hCT8Agft0vxYaycjyWtiu5Aw2hc2tKytWq+Lgi5Eb\npPSL18rxamvxMIJlERCmaoqJmDuNvGPtpv8TLlAz19ZEfrEIQs6J6k0G716cvZxE\nf4soMOrYismLOdHXsliIhvf4iHGnSMbIiN7jyjochK+maHTBE0GlOA==\n-----END RSA PRIVATE KEY-----\n"
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
)EOF";

class CiliumTLSProxyIntegrationTest : public CiliumTLSIntegrationTest {
public:
  CiliumTLSProxyIntegrationTest()
      : CiliumTLSIntegrationTest(fmt::format(
            TestEnvironment::substitute(cilium_tls_tcp_proxy_config_fmt, GetParam()), "true")) {}

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS_fmt, GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumTLSProxyIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

// Test upstream writing before downstream does.
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("hello"));
  tcp_client->waitForData("hello");

  ASSERT_TRUE(tcp_client->write("hello"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

// Test proxying data in both directions, and that all data is flushed properly
// when there is an upstream disconnect.
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(5));
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();
  tcp_client->close();

  EXPECT_EQ("world", tcp_client->data());
}

// Test proxying data in both directions, and that all data is flushed properly
// when the client disconnects.
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTcpProxyDownstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(5));
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  tcp_client->waitForData("world");
  ASSERT_TRUE(tcp_client->write("hello", true));
  ASSERT_TRUE(fake_upstream_connection->waitForData(10));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForDisconnect();
}

TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyLargeWrite) {
  config_helper_.setBufferLimits(1024, 1024);
  initialize();

  std::string data(1024 * 16, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write(data));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->write(data));
  tcp_client->waitForData(data);
  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.tls-cluster.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_EQ(upstream_pauses, upstream_resumes);

  uint32_t downstream_pauses =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_paused_reading_total")->value();
  uint32_t downstream_resumes =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_resumed_reading_total")->value();
  EXPECT_EQ(downstream_pauses, downstream_resumes);
}

// Test that a downstream flush works correctly (all data is flushed)
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size / 4, size / 4);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  tcp_client->readDisable(true);
  ASSERT_TRUE(tcp_client->write("", true));

  // This ensures that readDisable(true) has been run on it's thread
  // before tcp_client starts writing.
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  ASSERT_TRUE(fake_upstream_connection->write(data, true));

  test_server_->waitForCounterGe("cluster.tls-cluster.upstream_flow_control_paused_reading_total",
                                 1);
  EXPECT_EQ(test_server_->counter("cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
                ->value(),
            0);
  tcp_client->readDisable(false);
  tcp_client->waitForData(data);
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.tls-cluster.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_GE(upstream_pauses, upstream_resumes);
  EXPECT_GT(upstream_resumes, 0);
}

// Test that an upstream flush works correctly (all data is flushed)
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able
  // to wait for ConnectionEvent::Connected, which is raised after the TLS
  // handshake has completed, but just wait for a while instead for now.
  usleep(100000); // NO_CHECK_FORMAT(real_time)

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on
  // it's thread before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true, true, std::chrono::milliseconds(30000)));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  ASSERT_TRUE(
      fake_upstream_connection->waitForData(data.size(), nullptr, 3 * TestUtility::DefaultTimeout));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  tcp_client->waitForHalfClose();

  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 0);
}

// Test that Envoy doesn't crash or assert when shutting down with an upstream
// flush active
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamFlushEnvoyExit) {
  // Use a very large size to make sure it is larger than the kernel socket read
  // buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able
  // to wait for ConnectionEvent::Connected, which is raised after the TLS
  // handshake has completed, but just wait for a while instead for now.
  usleep(100000); // NO_CHECK_FORMAT(real_time)

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on
  // it's thread before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}

//
// Cilium filters with TCP proxy & Upstream TLS
//

// params: is_ingress ("true", "false")
const std::string cilium_tls_downstream_tcp_proxy_config_fmt = R"EOF(
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: tls-cluster
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    connect_timeout:
      seconds: 1
    transport_socket:
      name: "cilium.tls_wrapper"
      typed_config:
        "@type": type.googleapis.com/cilium.UpstreamTlsWrapperContext
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
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    listener_filters:
    - name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
    - name: "envoy.filters.listener.tls_inspector"
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector
    filter_chains:
    - filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: tls-cluster
    - filter_chain_match:
        transport_protocol: "tls"
      transport_socket:
        name: "cilium.tls_wrapper"
        typed_config:
          "@type": type.googleapis.com/cilium.DownstreamTlsWrapperContext
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: tls-cluster
)EOF";

class CiliumDownstreamTLSIntegrationTest : public CiliumTLSIntegrationTest {
public:
  CiliumDownstreamTLSIntegrationTest()
      : CiliumTLSIntegrationTest(fmt::format(
            TestEnvironment::substitute(cilium_tls_downstream_tcp_proxy_config_fmt, GetParam()),
            "true")) {}

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS_fmt, GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumDownstreamTLSIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                         TestUtility::ipTestParamsToString);

TEST_P(CiliumDownstreamTLSIntegrationTest, SendTlsToTlsListener) {
  setupConnections();
  sendAndReceiveTlsData("hello", "world");
}

TEST_P(CiliumDownstreamTLSIntegrationTest, LargeBidirectionalTlsWrites) {
  setupConnections();
  std::string large_data(1024 * 8, 'a');
  sendAndReceiveTlsData(large_data, large_data);
}

// Test that a half-close on the downstream side is proxied correctly.
TEST_P(CiliumDownstreamTLSIntegrationTest, DownstreamHalfClose) {
  setupConnections();

  FakeRawConnectionPtr fake_upstream_connection;
  AssertionResult result = fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
  RELEASE_ASSERT(result, result.message());

  Buffer::OwnedImpl empty_buffer;
  ssl_client_->write(empty_buffer, true);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  const std::string data("data");
  ASSERT_TRUE(fake_upstream_connection->write(data, false));
  payload_reader_->setDataToWaitFor(data);
  ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);
  EXPECT_FALSE(payload_reader_->readLastByte());

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);
  EXPECT_TRUE(payload_reader_->readLastByte());
  EXPECT_TRUE(connect_callbacks_.closed());
}

// Test that a half-close on the upstream side is proxied correctly.
TEST_P(CiliumDownstreamTLSIntegrationTest, UpstreamHalfClose) {
  setupConnections();

  FakeRawConnectionPtr fake_upstream_connection;
  AssertionResult result = fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
  RELEASE_ASSERT(result, result.message());

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);
  EXPECT_TRUE(payload_reader_->readLastByte());
  EXPECT_FALSE(connect_callbacks_.closed());

  const std::string& val("data");
  Buffer::OwnedImpl buffer(val);
  ssl_client_->write(buffer, false);
  while (client_write_buffer_->bytesDrained() != val.size()) {
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  }
  ASSERT_TRUE(fake_upstream_connection->waitForData(val.size()));

  Buffer::OwnedImpl empty_buffer;
  ssl_client_->write(empty_buffer, true);
  while (!connect_callbacks_.closed()) {
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  }
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

} // namespace Cilium
} // namespace Envoy
