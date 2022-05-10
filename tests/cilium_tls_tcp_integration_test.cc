#include "source/extensions/transport_sockets/tls/context_config_impl.h"
#include "source/extensions/transport_sockets/tls/ssl_socket.h"
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
  access_log_path: /dev/null
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
        "@type": type.googleapis.com/cilium.BpfMetadata
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
  CiliumTLSIntegrationTest(const std::string& config)
      : CiliumTcpIntegrationTest(config) {
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
      fake_upstreams_.emplace_back(new FakeUpstream(createUpstreamSslContext(), 0, version_, config));
    } else {
      CiliumTcpIntegrationTest::
          createUpstreams();  // maybe BaseIntegrationTest::createUpstreams()
    }
  }

  void TearDown() override { CiliumTcpIntegrationTest::TearDown(); }

  // TODO(mattklein123): This logic is duplicated in various places. Cleanup in
  // a follow up.
  Network::TransportSocketFactoryPtr createUpstreamSslContext() {
    envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext
        tls_context;
    auto* common_tls_context = tls_context.mutable_common_tls_context();
    auto* tls_cert = common_tls_context->add_tls_certificates();
    tls_cert->mutable_certificate_chain()->set_filename(
        TestEnvironment::runfilesPath(fmt::format(
            "test/config/integration/certs/{}cert.pem", upstream_cert_name_)));
    tls_cert->mutable_private_key()->set_filename(
        TestEnvironment::runfilesPath(fmt::format(
            "test/config/integration/certs/{}key.pem", upstream_cert_name_)));

    auto cfg = std::make_unique<
        Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static Stats::Scope* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<
        Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store,
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
        .WillOnce(Invoke(
            [&](std::function<void()> below_low,
                std::function<void()> above_high,
                std::function<void()> above_overflow) -> Buffer::Instance* {
              client_write_buffer_ = new NiceMock<MockWatermarkBuffer>(
                  below_low, above_high, above_overflow);
              ON_CALL(*client_write_buffer_, move(_))
                  .WillByDefault(Invoke(client_write_buffer_,
                                        &MockWatermarkBuffer::baseMove));
              ON_CALL(*client_write_buffer_, drain(_))
                  .WillByDefault(Invoke(client_write_buffer_,
                                        &MockWatermarkBuffer::trackDrains));
              return client_write_buffer_;
            }));
    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("tcp_proxy"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    ssl_client_ = dispatcher_->createClientConnection(
        address, Network::Address::InstanceConstSharedPtr(),
        context_->createTransportSocket(nullptr), nullptr);

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
    AssertionResult result =
        fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
    RELEASE_ASSERT(result, result.message());

    // Ship some data upstream.
    Buffer::OwnedImpl buffer(data_to_send_upstream);
    ssl_client_->write(buffer, false);
    while (client_write_buffer_->bytesDrained() !=
           data_to_send_upstream.size()) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }

    // Make sure the data makes it upstream.
    ASSERT_TRUE(
        fake_upstream_connection->waitForData(data_to_send_upstream.size()));

    // Now send data downstream and make sure it arrives.
    ASSERT_TRUE(fake_upstream_connection->write(data_to_send_downstream));
    payload_reader_->set_data_to_wait_for(data_to_send_downstream);
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
  Network::TransportSocketFactoryPtr context_;
  Network::ClientConnectionPtr ssl_client_;
  ConnectionStatusCallbacks connect_callbacks_;
};

// upstream_tls_context tructed_ca from
// test/config/integration/certs/upstreamcacert.pem downstream_tls_context
// certificate_chain from test/config/integration/certs/servercert.pem
// downstream_tls_context private_key from
// test/config/integration/certs/serverkey.pem
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
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUTQZdxxw6y4+Te1kv8hDza/KXTHUwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjAwODA1MTkx\nNjAyWhcNMjIwODA1MTkxNjAyWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFT8hbqRn+9AKU2\nIFtZKFFYpt7v2x1e8gtzgPm3TT7RJcV2GLeT1cOwubL81ArQmwfyVlwJkt1wK7Uw\n+Z4FvtcCjQc4dR3yxkIdhzZOiq7PbQgAjyRNNGmneYTAvpXwC+l8ZV2M66ihUKgj\n7iGiqQCvYhuYIb7BEnOj20nFuvHlxaDWOst4SQgZmRIkQyA8rrAIRfu7aQiCEla5\n86AXcXV4gmOW3dsKNoXO8Fr+9mtAmJKocLtlUkCeDW+WYqv6RLjMVa915khNQLde\nbL+5hYxBcKYB10wOVzSTCfM6fbqtpqJZEdlGjkKtQ2Szy3mpoAJKPmZYzodVhL6N\nLhoLjZ8CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFDtmHVOikybtJjVEI4Q7wvUbwgBkMB8GA1UdIwQYMBaAFDtmHVOi\nkybtJjVEI4Q7wvUbwgBkMA0GCSqGSIb3DQEBCwUAA4IBAQAT3kBm2uCpB4cAmdgu\nu6sqxUvYFzYlHFnWrQ3ZFwMrLRSzUdrcp2nSQz+e8VeXI2SkLPCD5Xg+8GGLWA5X\nlH6tvVx41cRqSr611ebxPVWkEeP+ALkHo4xUbcR5WUJD52VxzqYbhavYFjB2FzqA\nOfefKyXIhcKtezKBwaJbVn9FseH49q6UNjYODOY88rW+2mvDoZWBUuti8CxNhIiu\nRHnGimY7H565NpbPliVlo2GhiKhJvyPwK7+cjfj68HaoixlXHmrg506bczO/Gt1a\nUSQmjtB05h8bki0LQDiCQu1fdOPEflJnv3VdFz2SSKNRab2asP+KbRPURUW8f9zN\nGNxR\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEbDCCA1SgAwIBAgIUJuVBh0FKfFgIcO++ljWm7D47eYUwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjAwODA1MTkxNjAxWhcNMjIw\nODA1MTkxNjAxWjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC9JgaI7hxjPM0tsUna/QmivBdKbCrLnLW9Teak\nRH/Ebg68ovyvrRIlybDT6XhKi+iVpzVY9kqxhGHgrFDgGLBakVMiYJ5EjIgHfoo4\nUUAHwIYbunJluYCgANzpprBsvTC/yFYDVMqUrjvwHsoYYVm36io994k9+t813b70\no0l7/PraBsKkz8NcY2V2mrd/yHn/0HAhv3hl6iiJme9yURuDYQrae2ACSrQtsbel\nKwdZ/Re71Z1awz0OQmAjMa2HuCop+Q/1QLnqBekT5+DH1qKUzJ3Jkq6NRkERXOpi\n87j04rtCBteCogrO67qnuBZ2lH3jYEMb+lQdLkyNMLltBSdLAgMBAAGjgcAwgb0w\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMEEGA1UdEQQ6MDiGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYIIbHlmdC5jb22CDHd3dy5seWZ0LmNvbTAdBgNVHQ4EFgQU2XcTZbc0xKZf\ngNVKSvAbMZJCBoYwHwYDVR0jBBgwFoAUlkvaLFO0vpXGk3Pip6SfLg1yGIcwDQYJ\nKoZIhvcNAQELBQADggEBAFW05aca3hSiEz/g593GAV3XP4lI5kYUjGjbPSy/HmLr\nrdv/u3bGfacywAPo7yld+arMzd35tIYEqnhoq0+/OxPeyhwZXVVUatg5Oknut5Zv\n2+8l+mVW+8oFCXRqr2gwc8Xt4ByYN+HaNUYfoucnjDplOPukkfSuRhbxqnkhA14v\nLri2EbISX14sXf2VQ9I0dkm1hXUxiO0LlA1Z7tvJac9zPSoa6Oljke4D1iH2jzwF\nYn7S/gGvVQgkTmWrs3S3TGyBDi4GTDhCF1R+ESvXz8z4UW1MrCSdYUXbRtsT7sbE\nCjlFYuUyxCi1oe3IHCeXVDo/bmzwGQPDuF3WaDNSYWU=\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAvSYGiO4cYzzNLbFJ2v0JorwXSmwqy5y1vU3mpER/xG4OvKL8\nr60SJcmw0+l4Sovolac1WPZKsYRh4KxQ4BiwWpFTImCeRIyIB36KOFFAB8CGG7py\nZbmAoADc6aawbL0wv8hWA1TKlK478B7KGGFZt+oqPfeJPfrfNd2+9KNJe/z62gbC\npM/DXGNldpq3f8h5/9BwIb94ZeooiZnvclEbg2EK2ntgAkq0LbG3pSsHWf0Xu9Wd\nWsM9DkJgIzGth7gqKfkP9UC56gXpE+fgx9ailMydyZKujUZBEVzqYvO49OK7QgbX\ngqIKzuu6p7gWdpR942BDG/pUHS5MjTC5bQUnSwIDAQABAoIBADEMwlcSAFSPuNln\nhzJ9udj0k8md4T8p5Usw/2WLyeJDdBjg30wjQniAJBXgDmyueWMNmFz4iYgdP1CG\n/vYOEPV7iCZ7Da/TDZd77hYKo+MevuhD4lSU1VEoyCDjNA8OxKyHJB77BwmlYS+0\nnE3UOPLji47EOVfUTbvnRBSmn3DCSHkQiRIUP1xMivoiZgKJn+D+FxSMwwiq2pQR\n5tdo7nh2A8RxlYUbaD6i4poUB26HVm8vthXahNEkLpXQOz8MWRzs6xOdDHRzi9kT\nItRLa4A/3LIATqviQ2EpwcALHXcULcNUMTHORC1EHPvheWR5nLuRllYzN4ReoeHC\n3+A5KEkCgYEA52rlh/22/rLckCWugjyJic17vkg46feSOGhjuP2LelrIxNlg491y\no28n8lQPSVnEp3/sT7Y3quVvdboq4DC9LTzq52f6/mCYh9UQRpljuSmFqC2MPG46\nZl5KLEVLzhjC8aTWkhVINSpz9vauXderOpFYlPW32lnRTjJWE276kj8CgYEA0T2t\nULnn7TBvRSpmeWzEBA5FFo2QYkYvwrcVe0pfUltV6pf05xUmMXYFjpezSTEmPhh6\n+dZdhwxDk+6j8Oo61rTWucDsIqMj5ZT1hPNph8yQtb5LRlRbLGVrirU9Tp7xTgMq\n3uRA2Eka1d98dDBsEbMIVFSZ2MX3iezSGRL6j/UCgYEAxZQ82HjEDn2DVwb1EXjC\nLQdliTZ8cTXQf5yQ19aRiSuNkpPN536ga+1xe7JNQuEDx8auafg3Ww98tFT4WmUC\nf2ctX9klMJ4kXISK2twHioVq+gW5X7b04YXLajTX3eTCPDHyiNLmzY2raMWAZdrG\n9MA3kyafjCt3Sn4rg3gTM10CgYEAtJ8WRpJEd8aQttcUIItYZdvfnclUMtE9l0su\nGwCnalN3xguol/X0w0uLHn0rgeoQhhfhyFtY3yQiDcg58tRvODphBXZZIMlNSnic\nvEjW9ygKXyjGmA5nqdpezB0JsB2aVep8Dm5g35Ozu52xNCc8ksbGUO265Jp3xbMN\n5iEw9CUCgYBmfoPnJwzA5S1zMIqESUdVH6p3UwHU/+XTY6JHAnEVsE+BuLe3ioi7\n6dU4rFd845MCkunBlASLV8MmMbod9xU0vTVHPtmANaUCPxwUIxXQket09t19Dzg7\nA23sE+5myXtcfz6YrPhbLkijV4Nd7fmecodwDckvpBaWTMrv52/Www==\n-----END RSA PRIVATE KEY-----\n"
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
)EOF";

class CiliumTLSProxyIntegrationTest : public CiliumTLSIntegrationTest {
 public:
  CiliumTLSProxyIntegrationTest()
      : CiliumTLSIntegrationTest(
            fmt::format(TestEnvironment::substitute(
                            cilium_tls_tcp_proxy_config_fmt, GetParam()),
                        "true")) {}

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS_fmt, GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, CiliumTLSProxyIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
    TestUtility::ipTestParamsToString);

// Test upstream writing before downstream does.
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write("hello"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));
  ASSERT_TRUE(tcp_client->write(data));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->write(data));
  tcp_client->waitForData(data);
  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  uint32_t upstream_pauses =
      test_server_
          ->counter(
              "cluster.tls-cluster.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_
          ->counter(
              "cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_EQ(upstream_pauses, upstream_resumes);

  uint32_t downstream_pauses =
      test_server_
          ->counter(
              "tcp.tcp_stats.downstream_flow_control_paused_reading_total")
          ->value();
  uint32_t downstream_resumes =
      test_server_
          ->counter(
              "tcp.tcp_stats.downstream_flow_control_resumed_reading_total")
          ->value();
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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  tcp_client->readDisable(true);
  ASSERT_TRUE(tcp_client->write("", true));

  // This ensures that readDisable(true) has been run on it's thread
  // before tcp_client starts writing.
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  ASSERT_TRUE(fake_upstream_connection->write(data, true));

  test_server_->waitForCounterGe(
      "cluster.tls-cluster.upstream_flow_control_paused_reading_total", 1);
  EXPECT_EQ(
      test_server_
          ->counter(
              "cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
          ->value(),
      0);
  tcp_client->readDisable(false);
  tcp_client->waitForData(data);
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  uint32_t upstream_pauses =
      test_server_
          ->counter(
              "cluster.tls-cluster.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_
          ->counter(
              "cluster.tls-cluster.upstream_flow_control_resumed_reading_total")
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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able
  // to wait for ConnectionEvent::Connected, which is raised after the TLS
  // handshake has completed, but just wait for a while instead for now.
  usleep(100000);

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on
  // it's thread before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true, true, std::chrono::milliseconds(30000)));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(
      data.size(), nullptr, 3 * TestUtility::DefaultTimeout));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  tcp_client->waitForHalfClose();

  EXPECT_EQ(
      test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
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
  IntegrationTcpClientPtr tcp_client =
      makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able
  // to wait for ConnectionEvent::Connected, which is raised after the TLS
  // handshake has completed, but just wait for a while instead for now.
  usleep(100000);

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
  access_log_path: /dev/null
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
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    - name: "envoy.filters.listener.tls_inspector"
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
            TestEnvironment::substitute(
                cilium_tls_downstream_tcp_proxy_config_fmt, GetParam()),
            "true")) {}

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS_fmt, GetParam());
  }
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, CiliumDownstreamTLSIntegrationTest,
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
  AssertionResult result =
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
  RELEASE_ASSERT(result, result.message());

  Buffer::OwnedImpl empty_buffer;
  ssl_client_->write(empty_buffer, true);
  dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  const std::string data("data");
  ASSERT_TRUE(fake_upstream_connection->write(data, false));
  payload_reader_->set_data_to_wait_for(data);
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
  AssertionResult result =
      fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
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

}  // namespace Cilium
}  // namespace Envoy
