#include <fmt/base.h>
#include <fmt/format.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls.pb.h"
#include "envoy/http/codec.h" // IWYU pragma: keep
#include "envoy/network/address.h"
#include "envoy/network/connection.h"
#include "envoy/network/transport_socket.h"

#include "source/common/common/logger.h"
#include "source/common/stats/isolated_store_impl.h"
#include "source/common/tls/server_context_config_impl.h"
#include "source/common/tls/server_ssl_socket.h"

#include "test/integration/fake_upstream.h"
#include "test/integration/ssl_utility.h"
#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "tests/cilium_http_integration.h"
#include "tests/cilium_tls_integration.h"

namespace Envoy {
namespace Cilium {

//
// Cilium filters with HTTP proxy & Downstream/Upstream TLS
//

// params: is_ingress ("true", "false")
const std::string cilium_tls_http_proxy_config_fmt = R"EOF(
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
  - name: tls-cluster
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    connect_timeout:
      seconds: 1
    transport_socket:
      name: "cilium.tls_wrapper"
      typed_config:
        "@type": type.googleapis.com/cilium.UpstreamTlsWrapperContext
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        upstream_http_protocol_options:
          auto_sni: true
          auto_san_validation: true
        use_downstream_protocol_config: {{}}
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
    - name: test_bpf_metadata
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
          codec_type: auto
          http_filters:
          - name: test_l7policy
            typed_config:
              "@type": type.googleapis.com/cilium.L7Policy
              access_log_path: "{{ test_udsdir }}/access_log.sock"
          - name: envoy.filters.http.router
          route_config:
            name: policy_enabled
            virtual_hosts:
              name: integration
              domains: "*"
              routes:
              - route:
                  cluster: cluster1
                  max_grpc_timeout:
                    seconds: 0
                    nanos: 0
                match:
                  prefix: "/"
    - filter_chain_match:
        transport_protocol: "cilium:default"
        server_names: [ "localhost" ]
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            typed_config:
              "@type": type.googleapis.com/cilium.L7Policy
              access_log_path: "{{ test_udsdir }}/access_log.sock"
          - name: envoy.filters.http.router
          route_config:
            name: policy_enabled
            virtual_hosts:
              name: integration
              require_tls: ALL
              domains: "*"
              routes:
              - route:
                  cluster: tls-cluster
                  max_grpc_timeout:
                    seconds: 0
                    nanos: 0
                match:
                  prefix: "/"
      transport_socket:
        name: "cilium.tls_wrapper"
        typed_config:
          "@type": type.googleapis.com/cilium.DownstreamTlsWrapperContext
)EOF";

// certificate_chain from test/config/integration/certs/servercert.pem
// private_key from test/config/integration/certs/serverkey.pem
const std::string TLS_CERTS_CONFIG = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: tls-certs
  tls_certificate:
    certificate_chain:
      inline_string: "-----BEGIN CERTIFICATE-----\nMIIEhTCCA22gAwIBAgIUNzDvuqS9evGzfYlk2tSjLIefr2cwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjYwNDA4MTc0MTE1WhcNMjgw\nNDA3MTc0MTE1WjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQCqDSZQksOORUPislq3jaHTTcw1D6ZoDSAlafDn\n/CdSAdL97BvH7utG+PeJj0ysnfoJ0hvSE1jZOhJhoYv4JHq6ZNAxPsFTqg/rN41A\nqXZU6rNh5qYo+s80pA4V5xe7QXuaCZb9egXq7EJR8Jhq3rMq6bbcs7P6y7Qpms/j\nu/WNdrBVdnZneJu4eWWSjW4IFUafhYor+xuLVNy6VvUbAmGTKfi/q/0lhGRVMWHl\n66YVQAutB748odDx2Xr2gtpIs/0kJWL4SEn7u9D9NmbX5dw8FhBQBfLJsK6exCYt\n6liTKztSnzoS+IiqbO6tfOh0xecnPRSZPngBJylpKxfouL2BAgMBAAGjgdkwgdYw\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMFoGA1UdEQRTMFGGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYYXaHR0cDovL2JhY2tlbmQubHlmdC5jb22CCGx5ZnQuY29tggx3d3cubHlm\ndC5jb20wHQYDVR0OBBYEFGFsycovKOCEx1XZynNB6OEqPaUGMB8GA1UdIwQYMBaA\nFPmRww/tQ1LQH8ZMhrX2xn8yvmiUMA0GCSqGSIb3DQEBCwUAA4IBAQAvn7HxV9v8\nXT4mgxXpG6hgdx2i8OtcUM029zO0uNvkmwtLIrMbbdmu1Ph+IXLaukzoD0Vj9GrQ\nbXc6iqmH8SBLUwRcI5/WrGMnxvXi5o6fWWnjA/6TFFYGFq6s64aPdXBbZRR1Utxq\ndkWt9DUbTSSkWXat/mo4/JfTdChlNR+ZXGwgCRRd0jYVpEXTaCMwhmjR7qfNTqjI\nKHTHf+OYCDw2aOHU4YhfbSwt452lZJqPxSfu/aH3RtgyZlEx21vt2dZ5ZMeKy45a\nsic7zafXL3KatSQ1K4F7DUXq5uU99uitx4aVgN8vLLgHzXks/jMyho/R9TbsGk24\nWHrxMOOBWz1q\n-----END CERTIFICATE-----\n"
    private_key:
      inline_string: "-----BEGIN PRIVATE KEY-----\nMIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCqDSZQksOORUPi\nslq3jaHTTcw1D6ZoDSAlafDn/CdSAdL97BvH7utG+PeJj0ysnfoJ0hvSE1jZOhJh\noYv4JHq6ZNAxPsFTqg/rN41AqXZU6rNh5qYo+s80pA4V5xe7QXuaCZb9egXq7EJR\n8Jhq3rMq6bbcs7P6y7Qpms/ju/WNdrBVdnZneJu4eWWSjW4IFUafhYor+xuLVNy6\nVvUbAmGTKfi/q/0lhGRVMWHl66YVQAutB748odDx2Xr2gtpIs/0kJWL4SEn7u9D9\nNmbX5dw8FhBQBfLJsK6exCYt6liTKztSnzoS+IiqbO6tfOh0xecnPRSZPngBJylp\nKxfouL2BAgMBAAECgf8G2HJyaFmhoIu+m5oZgmhPg/XJ17PiUcFkMfTrYdCIvJhI\n56L9xeBrrMS8BOU01NHfhRzgtIMfHxPJBQYIGsUrWCq0Ca8iNi9DM3IuBKRiYyzH\nPQjW5JcrquDJ1kOzooSJC1nIr8RijRIB81ES/EedsqAw+ydnMS+k0nML9+GAAhLC\n/WKEdtPrxM0Uxllw5Vf9/M4zxcCDTpmD+gpchA1Ni5EqJsOILjkbQV3kM9fN93uw\nuoEK2cMfzYAEakc1y+aizhFEw1PYA+CrOU9Vw81OsTRgwjKPsJYQdqUj3pA4vu5m\npjCKXGv0T5pJepFBcDLoCgcSiMXoqTdAycx9vqUCgYEA3YlDGjlHdkkw30a1oNA8\nfDEKN/CYQYTPhtMNc9YyXR7L7kfTg+33pl5dMgRu16DD4RnbYyajfPNu8TncJGGo\n4KgYo4x+/cs+MrKrI2pnEPHfUVrLAjEkeQAkb/ujVJMs4veVfneO6CTUNKduWuEE\njuLYRvqc+k4WiJ9/maJXLX0CgYEAxIF9sZB5/jI7avk5cOn94Tlm0VA4hEXqu5rd\n2Xk8bxTM6lgykwXeuvlvawcZI9e+2hR4QmpV/Et3Ui0pYK1L+Zdd8rnUtd7V9i8u\no0I8mTGEa8qsTLQwOPfIvflV+MSPl6RAwT8SPktgG6TPPIqkzfrbvx4g2CBYvoXx\n961+n1UCgYBjxuenDvdFqi9N0J4LQN6NHNU6Xq1kjPmfAr2DV4y1biJxPn5gZDRv\nBP86gM6fZXPzlV6/KG7n3wgvs1yYMjgKfwsh1ix4CCsKUHhN6iVjd1yaWqcmZJXF\nva+rlA17ERJdYx88p4KAwd2lnWdRnRkddcPtLAC5p6P0gsnIm1piTQKBgQCH/4qr\nUm9rwv4mafgcMoV3089Z++gxe2YakvMJaQOvaTjs0z+lS0G8K5e1/gKjMNSwf8w/\nQvLhmqUpJYJmm2ligyUNMRmLCX8RU9Q2P0hLSd747xrSNz7Mnoi7Gg4rDnbGn3IF\njI4muOn6F9UpdFbdC8n7+nEGw1RH/9HX9aYVxQKBgA1j72+E+gmFmw4xwKvQ34Ni\nk2f/pHQCguaXiSezD/4+66tIQkD9scA4mnfuDz/GiO229+tRatW4vCEaC3i7VO2S\nEX3MB3Cdzea9QB1agCXowt7d2PcdVmbf6j5i9iUzK8pj6fKcFGFcZHi3fy8j2TlP\nyixlQCLUlSUGT4S7vVPu\n-----END PRIVATE KEY-----\n"
)EOF";

// trusted_ca from test/config/integration/certs/upstreamcacert.pem
const std::string CA_CERTS_CONFIG = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: ca-certs
  validation_context:
    trusted_ca:
      inline_string: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUJztoEG8UKqneO2edPl1Yiq2IjNkwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjYwNDA4MTc0\nMTE2WhcNMjgwNDA3MTc0MTE2WjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKjZZotuzFxABURb\nOSG22zv1GbghopySYNnD/JujZpP3GbHSx/urxT25AMRJYQu60m5cO7z9cL012mvx\nLGAbSbrC1adMxCtVr/f18JHpSrzexWJNSwAFy0ZozTVmgI2jBCDhgj0e5lVqVY8Y\nk1G3uehZqWgg5I/A+037jash82CRaJfDfzSwaZPaXsFMgUbP70cd2QKIofc2lFBv\nk72YqvsfsyljucpxRtCKycyNiZCFxt5GicrRMg23EOUfeEjVpWTo0T+YVYGrIhnu\n2ry5bOC9mC8zb/t/ofSkB4EpmV38liGVuN6RG2gL5gl4TIG6oAJiWcq1mbFIWlUP\ndIXFbaMCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFHJ9lGcvI3/c/MUKnEy2bFKvXgqpMB8GA1UdIwQYMBaAFHJ9lGcv\nI3/c/MUKnEy2bFKvXgqpMA0GCSqGSIb3DQEBCwUAA4IBAQAWnA0xp1ZQS6clgBrN\ndc9oc9qphYnNZssCNniAp9fQu+CF1FD9f3AqF9LzepVzh4X3E6Tpaxpf5xNVHg6S\ngaAIWvvZfOilZUh2bT4+wUs9sARXOaO06YddMi5Mwjt3t+GeBQIfxFl33J4h3VT8\nIrIlHHPdhiyWrOcGl3YYLlAvY28erq+KgqlMVbpmx/qkk3GPMZ9EswDxH92TU352\nGtkc7QibmaK42LY+XrcoPgIMXlrELZ6lr/VPSexYgChUMJ2KoQ4NK1rgQK8+KqlX\nDvkbWB0/CZa/wqno48cswMO0/rIhJOHXPpRmrCJC/ka+ywtMhRf1YYiROXs6iDPQ\nOH5l\n-----END CERTIFICATE-----\n"
)EOF";

const std::string BASIC_TLS_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ {{ name: ':path', exact_match: '/allowed' }} ]
        - headers: [ {{ name: ':path', safe_regex_match: {{ google_re2: {{}}, regex: '.*public$' }} }} ]
        - headers: [ {{ name: ':authority', exact_match: 'allowedHOST' }} ]
        - headers: [ {{ name: ':authority', safe_regex_match: {{ google_re2: {{}}, regex: '.*REGEX.*' }} }} ]
        - headers: [ {{ name: ':method', exact_match: 'PUT' }}, {{ name: ':path', exact_match: '/public/opinions' }} ]
      upstream_tls_context:
        validation_context_sds_secret: ca-certs
      downstream_tls_context:
        tls_sds_secret: tls-certs
        alpn_protocols: [ "h2", "http/1.1" ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ {{ name: ':path', exact_match: '/only-2-allowed' }} ]
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ {{ name: ':path', exact_match: '/allowed' }} ]
        - headers: [ {{ name: ':path', safe_regex_match: {{ google_re2: {{}}, regex: '.*public$' }} }} ]
        - headers: [ {{ name: ':authority', exact_match: 'allowedHOST' }} ]
        - headers: [ {{ name: ':authority', safe_regex_match: {{ google_re2: {{}}, regex: '.*REGEX.*' }} }} ]
        - headers: [ {{ name: ':method', exact_match: 'PUT' }}, {{ name: ':path', exact_match: '/public/opinions' }} ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ {{ name: ':path', exact_match: '/only-2-allowed' }} ]
)EOF";

/*
 * Use filter_chain_match on a requestedServerName that is set by the cilium bpf
 * metadata filter based on the applicable network policy?
 * "example.domain.name.namespace"
 */
class CiliumHttpTLSIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumHttpTLSIntegrationTest(const std::string& config) : CiliumHttpIntegrationTest(config) {}
  ~CiliumHttpTLSIntegrationTest() override = default;

  void initialize() override {
    CiliumHttpIntegrationTest::initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("http"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    Network::ClientConnectionPtr ssl_client = dispatcher_->createClientConnection(
        address, Network::Address::InstanceConstSharedPtr(),
        context_->createTransportSocket(nullptr, nullptr), nullptr, nullptr);

    ssl_client->enableHalfClose(true);
    codec_client_ = makeHttpConnection(std::move(ssl_client));
  }

  void createUpstreams() override {
    if (upstream_tls_) {
      auto config = upstreamConfig();
      config.upstream_protocol_ = FakeHttpConnection::Type::HTTP1;
      config.enable_half_close_ = true;
      fake_upstreams_.emplace_back(
          new FakeUpstream(createUpstreamSslContext(), 0, version_, config));
    } else {
      CiliumHttpIntegrationTest::createUpstreams();
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
    ENVOY_LOG_MISC(debug, "Fake Upstream Downstream TLS context: {}", tls_context.DebugString());

    auto server_config_or_error =
        Extensions::TransportSockets::Tls::ServerContextConfigImpl::create(tls_context,
                                                                           factory_context_, false);
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    THROW_IF_NOT_OK(server_config_or_error.status());
    auto cfg = std::move(server_config_or_error.value());

    static auto* upstream_stats_store = new Stats::IsolatedStoreImpl();
    auto factory_or_error = Extensions::TransportSockets::Tls::ServerSslSocketFactory::create(
        std::move(cfg), context_manager_, *upstream_stats_store->rootScope(),
        std::vector<std::string>{});
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    THROW_IF_NOT_OK(factory_or_error.status());
    return std::move(factory_or_error.value());
  }

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(BASIC_TLS_POLICY_fmt, GetParam());
  }

  std::vector<std::pair<std::string, std::string>> testSecrets() override {
    return std::vector<std::pair<std::string, std::string>>{
        {"tls-certs", TLS_CERTS_CONFIG},
        {"ca-certs", CA_CERTS_CONFIG},
    };
  }

  void denied(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("403", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }

  void failed(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("503", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }

  void accepted(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().getStatusValue());
    EXPECT_TRUE(upstream_request_->complete());
    EXPECT_EQ(0, upstream_request_->bodyLength());
    cleanupUpstreamAndDownstream();
  }

  // Upstream
  bool upstream_tls_{true};
  std::string upstream_cert_name_{"upstreamlocalhost"};

  // Downstream
  Network::UpstreamTransportSocketFactoryPtr context_;
};

class CiliumTLSHttpIntegrationTest : public CiliumHttpTLSIntegrationTest {
public:
  CiliumTLSHttpIntegrationTest()
      : CiliumHttpTLSIntegrationTest(fmt::format(
            fmt::runtime(TestEnvironment::substitute(cilium_tls_http_proxy_config_fmt, GetParam())),
            "true")) {}
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumTLSHttpIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPathPrefix) {
  denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefix) {
  accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefixStrippedHeader) {
  accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "localhost"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathRegex) {
  accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPath) {
  denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedMethod) {
  denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AcceptedMethod) {
  accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, L3DeniedPath) {
  denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "localhost"}});
}

} // namespace Cilium

} // namespace Envoy
