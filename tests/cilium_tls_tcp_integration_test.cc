#include <fmt/base.h>
#include <fmt/format.h>
#include <gmock/gmock-cardinalities.h>
#include <gmock/gmock-spec-builders.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "envoy/buffer/buffer.h"
#include "envoy/event/dispatcher.h"
#include "envoy/http/codec.h" // IWYU pragma: keep
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"
#include "envoy/ssl/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/buffer/watermark_buffer.h"
#include "source/common/common/assert.h"

#include "test/integration/fake_upstream.h"
#include "test/integration/integration_tcp_client.h"
#include "test/integration/ssl_utility.h"
#include "test/integration/utility.h"
#include "test/mocks/buffer/mocks.h"
#include "test/mocks/server/admin.h"
#include "test/test_common/environment.h"
#include "test/test_common/test_time_system.h"
#include "test/test_common/utility.h"

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

    payload_reader_ = std::make_shared<WaitForPayloadReader>(*dispatcher_);
  }

  AssertionResult
  waitForTlsHandshake(const FakeRawConnection& connection,
                      std::chrono::milliseconds timeout = TestUtility::DefaultTimeout) {
    Event::TestTimeSystem::RealTimeBound bound(timeout);
    while (true) {
      const auto downstream_timing = connection.connection().streamInfo().downstreamTiming();
      if (downstream_timing.downstreamHandshakeComplete().has_value()) {
        return AssertionSuccess();
      }

      // client-side TLS I/O will not progress unless the test-thread dispatcher runs
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);

      timeSystem().advanceTimeWait(std::chrono::milliseconds(1));

      if (timeout != std::chrono::milliseconds::zero() && !bound.withinBound()) {
        const Ssl::ConnectionInfoConstSharedPtr ssl = connection.connection().ssl();
        return AssertionFailure() << "Timed out waiting for TLS handshake. ssl=" << (ssl != nullptr)
                                  << " handshake_complete="
                                  << downstream_timing.downstreamHandshakeComplete().has_value()
                                  << " tls_version=" << (ssl != nullptr ? ssl->tlsVersion() : "")
                                  << " ciphersuite="
                                  << (ssl != nullptr ? ssl->ciphersuiteString() : "");
      }
    }
  }

  void createUpstreams() override {
    auto config = upstreamConfig();
    config.upstream_protocol_ = FakeHttpConnection::Type::HTTP1;
    config.enable_half_close_ = true;
    fake_upstreams_.emplace_back(new FakeUpstream(createUpstreamSslContext(), 0, version_, config));
  }

  Network::DownstreamTransportSocketFactoryPtr createUpstreamSslContext() {
    return Ssl::createFakeUpstreamSslContext(upstream_cert_name_, context_manager_,
                                             factory_context_);
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
        }))
        .WillRepeatedly(Invoke([](std::function<void()> below_low, std::function<void()> above_high,
                                  std::function<void()> above_overflow) -> Buffer::Instance* {
          return new Buffer::WatermarkBuffer(below_low, above_high, above_overflow);
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

    // Wait for TLS handshake first to get a clear error signal if it never completes.
    ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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

    // FakeRawConnection removes its read filter on the fake-upstream dispatcher in its
    // destructor, so drop it before we start tearing down the client side and the fixture.
    fake_upstream_connection.reset();
    teardownConnections();
  }

  void teardownConnections() {
    ssl_client_.reset();
    // Client connection teardown uses deferred delete on the test dispatcher. Flush one
    // non-blocking pass before releasing the helper objects that were attached to the connection.
    dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    context_.reset();
    client_write_buffer_ = nullptr;
    payload_reader_.reset();
    connect_callbacks_.reset();
  }

  // Upstream
  std::string upstream_cert_name_{"upstreamlocalhost"};

  // Downstream
  std::shared_ptr<WaitForPayloadReader> payload_reader_;
  MockWatermarkBuffer* client_write_buffer_;
  Network::UpstreamTransportSocketFactoryPtr context_;
  ConnectionStatusCallbacks connect_callbacks_;
  Network::ClientConnectionPtr ssl_client_;
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
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUJztoEG8UKqneO2edPl1Yiq2IjNkwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjYwNDA4MTc0\nMTE2WhcNMjgwNDA3MTc0MTE2WjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjZZotuzFxABURb\nOSG22zv1GbghopySYNnD/JujZpP3GbHSx/urxT25AMRJYQu60m5cO7z9cL012mvx\nLGAbSbrC1adMxCtVr/f18JHpSrzexWJNSwAFy0ZozTVmgI2jBCDhgj0e5lVqVY8Y\nk1G3uehZqWgg5I/A+037jash82CRaJfDfzSwaZPaXsFMgUbP70cd2QKIofc2lFBv\nk72YqvsfsyljucpxRtCKycyNiZCFxt5GicrRMg23EOUfeEjVpWTo0T+YVYGrIhnu\n2ry5bOC9mC8zb/t/ofSkB4EpmV38liGVuN6RG2gL5gl4TIG6oAJiWcq1mbFIWlUP\ndIXFbaMCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFHJ9lGcvI3/c/MUKnEy2bFKvXgqpMB8GA1UdIwQYMBaAFHJ9lGcv\nI3/c/MUKnEy2bFKvXgqpMA0GCSqGSIb3DQEBCwUAA4IBAQAWnA0xp1ZQS6clgBrN\ndc9oc9qphYnNZssCNniAp9fQu+CF1FD9f3AqF9LzepVzh4X3E6Tpaxpf5xNVHg6S\ngaAIWvvZfOilZUh2bT4+wUs9sARXOaO06YddMi5Mwjt3t+GeBQIfxFl33J4h3VT8\nIrIlHHPdhiyWrOcGl3YYLlAvY28erq+KgqlMVbpmx/qkk3GPMZ9EswDxH92TU352\nGtkc7QibmaK42LY+XrcoPgIMXlrELZ6lr/VPSexYgChUMJ2KoQ4NK1rgQK8+KqlX\nDvkbWB0/CZa/wqno48cswMO0/rIhJOHXPpRmrCJC/ka+ywtMhRf1YYiROXs6iDPQ\nOH5l\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEhTCCA22gAwIBAgIUNzDvuqS9evGzfYlk2tSjLIefr2cwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjYwNDA4MTc0MTE1WhcNMjgw\nNDA3MTc0MTE1WjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQCqDSZQksOORUPislq3jaHTTcw1D6ZoDSAlafDn\n/CdSAdL97BvH7utG+PeJj0ysnfoJ0hvSE1jZOhJhoYv4JHq6ZNAxPsFTqg/rN41A\nqXZU6rNh5qYo+s80pA4V5xe7QXuaCZb9egXq7EJR8Jhq3rMq6bbcs7P6y7Qpms/j\nu/WNdrBVdnZneJu4eWWSjW4IFUafhYor+xuLVNy6VvUbAmGTKfi/q/0lhGRVMWHl\n66YVQAutB748odDx2Xr2gtpIs/0kJWL4SEn7u9D9NmbX5dw8FhBQBfLJsK6exCYt\n6liTKztSnzoS+IiqbO6tfOh0xecnPRSZPngBJylpKxfouL2BAgMBAAGjgdkwgdYw\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMFoGA1UdEQRTMFGGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYYXaHR0cDovL2JhY2tlbmQubHlmdC5jb22CCGx5ZnQuY29tggx3d3cubHlm\ndC5jb20wHQYDVR0OBBYEFGFsycovKOCEx1XZynNB6OEqPaUGMB8GA1UdIwQYMBaA\nFPmRww/tQ1LQH8ZMhrX2xn8yvmiUMA0GCSqGSIb3DQEBCwUAA4IBAQAvn7HxV9v8\nXT4mgxXpG6hgdx2i8OtcUM029zO0uNvkmwtLIrMbbdmu1Ph+IXLaukzoD0Vj9GrQ\nbXc6iqmH8SBLUwRcI5/WrGMnxvXi5o6fWWnjA/6TFFYGFq6s64aPdXBbZRR1Utxq\ndkWt9DUbTSSkWXat/mo4/JfTdChlNR+ZXGwgCRRd0jYVpEXTaCMwhmjR7qfNTqjI\nKHTHf+OYCDw2aOHU4YhfbSwt452lZJqPxSfu/aH3RtgyZlEx21vt2dZ5ZMeKy45a\nsic7zafXL3KatSQ1K4F7DUXq5uU99uitx4aVgN8vLLgHzXks/jMyho/R9TbsGk24\nWHrxMOOBWz1q\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCqDSZQksOORUPi\nslq3jaHTTcw1D6ZoDSAlafDn/CdSAdL97BvH7utG+PeJj0ysnfoJ0hvSE1jZOhJh\noYv4JHq6ZNAxPsFTqg/rN41AqXZU6rNh5qYo+s80pA4V5xe7QXuaCZb9egXq7EJR\n8Jhq3rMq6bbcs7P6y7Qpms/ju/WNdrBVdnZneJu4eWWSjW4IFUafhYor+xuLVNy6\nVvUbAmGTKfi/q/0lhGRVMWHl66YVQAutB748odDx2Xr2gtpIs/0kJWL4SEn7u9D9\nNmbX5dw8FhBQBfLJsK6exCYt6liTKztSnzoS+IiqbO6tfOh0xecnPRSZPngBJylp\nKxfouL2BAgMBAAECgf8G2HJyaFmhoIu+m5oZgmhPg/XJ17PiUcFkMfTrYdCIvJhI\n56L9xeBrrMS8BOU01NHfhRzgtIMfHxPJBQYIGsUrWCq0Ca8iNi9DM3IuBKRiYyzH\nPQjW5JcrquDJ1kOzooSJC1nIr8RijRIB81ES/EedsqAw+ydnMS+k0nML9+GAAhLC\n/WKEdtPrxM0Uxllw5Vf9/M4zxcCDTpmD+gpchA1Ni5EqJsOILjkbQV3kM9fN93uw\nuoEK2cMfzYAEakc1y+aizhFEw1PYA+CrOU9Vw81OsTRgwjKPsJYQdqUj3pA4vu5m\npjCKXGv0T5pJepFBcDLoCgcSiMXoqTdAycx9vqUCgYEA3YlDGjlHdkkw30a1oNA8\nfDEKN/CYQYTPhtMNc9YyXR7L7kfTg+33pl5dMgRu16DD4RnbYyajfPNu8TncJGGo\n4KgYo4x+/cs+MrKrI2pnEPHfUVrLAjEkeQAkb/ujVJMs4veVfneO6CTUNKduWuEE\njuLYRvqc+k4WiJ9/maJXLX0CgYEAxIF9sZB5/jI7avk5cOn94Tlm0VA4hEXqu5rd\n2Xk8bxTM6lgykwXeuvlvawcZI9e+2hR4QmpV/Et3Ui0pYK1L+Zdd8rnUtd7V9i8u\no0I8mTGEa8qsTLQwOPfIvflV+MSPl6RAwT8SPktgG6TPPIqkzfrbvx4g2CBYvoXx\n961+n1UCgYBjxuenDvdFqi9N0J4LQN6NHNU6Xq1kjPmfAr2DV4y1biJxPn5gZDRv\nBP86gM6fZXPzlV6/KG7n3wgvs1yYMjgKfwsh1ix4CCsKUHhN6iVjd1yaWqcmZJXF\nva+rlA17ERJdYx88p4KAwd2lnWdRnRkddcPtLAC5p6P0gsnIm1piTQKBgQCH/4qr\nUm9rwv4mafgcMoV3089Z++gxe2YakvMJaQOvaTjs0z+lS0G8K5e1/gKjMNSwf8w/\nQvLhmqUpJYJmm2ligyUNMRmLCX8RU9Q2P0hLSd747xrSNz7Mnoi7Gg4rDnbGn3IF\njI4muOn6F9UpdFbdC8n7+nEGw1RH/9HX9aYVxQKBgA1j72+E+gmFmw4xwKvQ34Ni\nk2f/pHQCguaXiSezD/4+66tIQkD9scA4mnfuDz/GiO229+tRatW4vCEaC3i7VO2S\nEX3MB3Cdzea9QB1agCXowt7d2PcdVmbf6j5i9iUzK8pj6fKcFGFcZHi3fy8j2TlP\nyixlQCLUlSUGT4S7vVPu\n-----END PRIVATE KEY-----\n"
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
)EOF";

class CiliumTLSProxyIntegrationTest : public CiliumTLSIntegrationTest {
public:
  CiliumTLSProxyIntegrationTest()
      : CiliumTLSIntegrationTest(fmt::format(
            fmt::runtime(TestEnvironment::substitute(cilium_tls_tcp_proxy_config_fmt, GetParam())),
            "true")) {}

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
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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

  // Disabling read before the TLS handshake completes can stall the connection.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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

  // Disabling read before the TLS handshake completes can stall the connection.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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

  // Disabling read before the TLS handshake completes can stall the connection.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
      : CiliumTLSIntegrationTest(
            fmt::format(fmt::runtime(TestEnvironment::substitute(
                            cilium_tls_downstream_tcp_proxy_config_fmt, GetParam())),
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
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
  // Drop the fake-upstream wrapper before client-side teardown so its read-filter removal runs
  // while the fake-upstream dispatcher is still unquestionably alive.
  fake_upstream_connection.reset();
  teardownConnections();
}

// Test that a half-close on the upstream side is proxied correctly.
TEST_P(CiliumDownstreamTLSIntegrationTest, UpstreamHalfClose) {
  setupConnections();

  FakeRawConnectionPtr fake_upstream_connection;
  AssertionResult result = fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
  RELEASE_ASSERT(result, result.message());
  // Wait for TLS handshake first to get a clear error signal if it never completes.
  ASSERT_TRUE(waitForTlsHandshake(*fake_upstream_connection));

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
  // Drop the fake-upstream wrapper before client-side teardown so its read-filter removal runs
  // while the fake-upstream dispatcher is still unquestionably alive.
  fake_upstream_connection.reset();
  teardownConnections();
}

} // namespace Cilium
} // namespace Envoy
