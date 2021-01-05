#include "extensions/transport_sockets/tls/context_config_impl.h"
#include "extensions/transport_sockets/tls/ssl_socket.h"

#include "test/integration/ssl_utility.h"

#include "tests/bpf_metadata.h"   // policy_config
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
  access_log_path: /dev/null
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
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
    - filters:
      - name: cilium.network
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            typed_config:
              "@type": type.googleapis.com/cilium.L7Policy
              access_log_path: "{{ test_udsdir }}/access_log.sock"
          - name: envoy.router
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
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.http_connection_manager.v2.HttpConnectionManager
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            typed_config:
              "@type": type.googleapis.com/cilium.L7Policy
              access_log_path: "{{ test_udsdir }}/access_log.sock"
          - name: envoy.router
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
)EOF";

// upstream_tls_context tructed_ca from test/config/integration/certs/upstreamcacert.pem
// downstream_tls_context certificate_chain from test/config/integration/certs/servercert.pem
// downstream_tls_context private_key from test/config/integration/certs/serverkey.pem
const std::string BASIC_TLS_POLICY = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/allowed' } ]
        - headers: [ { name: ':path', safe_regex_match: { google_re2: {}, regex: '.*public$' } } ]
        - headers: [ { name: ':authority', exact_match: 'allowedHOST' } ]
        - headers: [ { name: ':authority', safe_regex_match: { google_re2: {}, regex: '.*REGEX.*' } } ]
        - headers: [ { name: ':method', exact_match: 'PUT' }, { name: ':path', exact_match: '/public/opinions' } ]
      upstream_tls_context:
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUTQZdxxw6y4+Te1kv8hDza/KXTHUwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjAwODA1MTkx\nNjAyWhcNMjIwODA1MTkxNjAyWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOFT8hbqRn+9AKU2\nIFtZKFFYpt7v2x1e8gtzgPm3TT7RJcV2GLeT1cOwubL81ArQmwfyVlwJkt1wK7Uw\n+Z4FvtcCjQc4dR3yxkIdhzZOiq7PbQgAjyRNNGmneYTAvpXwC+l8ZV2M66ihUKgj\n7iGiqQCvYhuYIb7BEnOj20nFuvHlxaDWOst4SQgZmRIkQyA8rrAIRfu7aQiCEla5\n86AXcXV4gmOW3dsKNoXO8Fr+9mtAmJKocLtlUkCeDW+WYqv6RLjMVa915khNQLde\nbL+5hYxBcKYB10wOVzSTCfM6fbqtpqJZEdlGjkKtQ2Szy3mpoAJKPmZYzodVhL6N\nLhoLjZ8CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFDtmHVOikybtJjVEI4Q7wvUbwgBkMB8GA1UdIwQYMBaAFDtmHVOi\nkybtJjVEI4Q7wvUbwgBkMA0GCSqGSIb3DQEBCwUAA4IBAQAT3kBm2uCpB4cAmdgu\nu6sqxUvYFzYlHFnWrQ3ZFwMrLRSzUdrcp2nSQz+e8VeXI2SkLPCD5Xg+8GGLWA5X\nlH6tvVx41cRqSr611ebxPVWkEeP+ALkHo4xUbcR5WUJD52VxzqYbhavYFjB2FzqA\nOfefKyXIhcKtezKBwaJbVn9FseH49q6UNjYODOY88rW+2mvDoZWBUuti8CxNhIiu\nRHnGimY7H565NpbPliVlo2GhiKhJvyPwK7+cjfj68HaoixlXHmrg506bczO/Gt1a\nUSQmjtB05h8bki0LQDiCQu1fdOPEflJnv3VdFz2SSKNRab2asP+KbRPURUW8f9zN\nGNxR\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEbDCCA1SgAwIBAgIUJuVBh0FKfFgIcO++ljWm7D47eYUwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjAwODA1MTkxNjAxWhcNMjIw\nODA1MTkxNjAxWjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC9JgaI7hxjPM0tsUna/QmivBdKbCrLnLW9Teak\nRH/Ebg68ovyvrRIlybDT6XhKi+iVpzVY9kqxhGHgrFDgGLBakVMiYJ5EjIgHfoo4\nUUAHwIYbunJluYCgANzpprBsvTC/yFYDVMqUrjvwHsoYYVm36io994k9+t813b70\no0l7/PraBsKkz8NcY2V2mrd/yHn/0HAhv3hl6iiJme9yURuDYQrae2ACSrQtsbel\nKwdZ/Re71Z1awz0OQmAjMa2HuCop+Q/1QLnqBekT5+DH1qKUzJ3Jkq6NRkERXOpi\n87j04rtCBteCogrO67qnuBZ2lH3jYEMb+lQdLkyNMLltBSdLAgMBAAGjgcAwgb0w\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMEEGA1UdEQQ6MDiGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYIIbHlmdC5jb22CDHd3dy5seWZ0LmNvbTAdBgNVHQ4EFgQU2XcTZbc0xKZf\ngNVKSvAbMZJCBoYwHwYDVR0jBBgwFoAUlkvaLFO0vpXGk3Pip6SfLg1yGIcwDQYJ\nKoZIhvcNAQELBQADggEBAFW05aca3hSiEz/g593GAV3XP4lI5kYUjGjbPSy/HmLr\nrdv/u3bGfacywAPo7yld+arMzd35tIYEqnhoq0+/OxPeyhwZXVVUatg5Oknut5Zv\n2+8l+mVW+8oFCXRqr2gwc8Xt4ByYN+HaNUYfoucnjDplOPukkfSuRhbxqnkhA14v\nLri2EbISX14sXf2VQ9I0dkm1hXUxiO0LlA1Z7tvJac9zPSoa6Oljke4D1iH2jzwF\nYn7S/gGvVQgkTmWrs3S3TGyBDi4GTDhCF1R+ESvXz8z4UW1MrCSdYUXbRtsT7sbE\nCjlFYuUyxCi1oe3IHCeXVDo/bmzwGQPDuF3WaDNSYWU=\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAvSYGiO4cYzzNLbFJ2v0JorwXSmwqy5y1vU3mpER/xG4OvKL8\nr60SJcmw0+l4Sovolac1WPZKsYRh4KxQ4BiwWpFTImCeRIyIB36KOFFAB8CGG7py\nZbmAoADc6aawbL0wv8hWA1TKlK478B7KGGFZt+oqPfeJPfrfNd2+9KNJe/z62gbC\npM/DXGNldpq3f8h5/9BwIb94ZeooiZnvclEbg2EK2ntgAkq0LbG3pSsHWf0Xu9Wd\nWsM9DkJgIzGth7gqKfkP9UC56gXpE+fgx9ailMydyZKujUZBEVzqYvO49OK7QgbX\ngqIKzuu6p7gWdpR942BDG/pUHS5MjTC5bQUnSwIDAQABAoIBADEMwlcSAFSPuNln\nhzJ9udj0k8md4T8p5Usw/2WLyeJDdBjg30wjQniAJBXgDmyueWMNmFz4iYgdP1CG\n/vYOEPV7iCZ7Da/TDZd77hYKo+MevuhD4lSU1VEoyCDjNA8OxKyHJB77BwmlYS+0\nnE3UOPLji47EOVfUTbvnRBSmn3DCSHkQiRIUP1xMivoiZgKJn+D+FxSMwwiq2pQR\n5tdo7nh2A8RxlYUbaD6i4poUB26HVm8vthXahNEkLpXQOz8MWRzs6xOdDHRzi9kT\nItRLa4A/3LIATqviQ2EpwcALHXcULcNUMTHORC1EHPvheWR5nLuRllYzN4ReoeHC\n3+A5KEkCgYEA52rlh/22/rLckCWugjyJic17vkg46feSOGhjuP2LelrIxNlg491y\no28n8lQPSVnEp3/sT7Y3quVvdboq4DC9LTzq52f6/mCYh9UQRpljuSmFqC2MPG46\nZl5KLEVLzhjC8aTWkhVINSpz9vauXderOpFYlPW32lnRTjJWE276kj8CgYEA0T2t\nULnn7TBvRSpmeWzEBA5FFo2QYkYvwrcVe0pfUltV6pf05xUmMXYFjpezSTEmPhh6\n+dZdhwxDk+6j8Oo61rTWucDsIqMj5ZT1hPNph8yQtb5LRlRbLGVrirU9Tp7xTgMq\n3uRA2Eka1d98dDBsEbMIVFSZ2MX3iezSGRL6j/UCgYEAxZQ82HjEDn2DVwb1EXjC\nLQdliTZ8cTXQf5yQ19aRiSuNkpPN536ga+1xe7JNQuEDx8auafg3Ww98tFT4WmUC\nf2ctX9klMJ4kXISK2twHioVq+gW5X7b04YXLajTX3eTCPDHyiNLmzY2raMWAZdrG\n9MA3kyafjCt3Sn4rg3gTM10CgYEAtJ8WRpJEd8aQttcUIItYZdvfnclUMtE9l0su\nGwCnalN3xguol/X0w0uLHn0rgeoQhhfhyFtY3yQiDcg58tRvODphBXZZIMlNSnic\nvEjW9ygKXyjGmA5nqdpezB0JsB2aVep8Dm5g35Ozu52xNCc8ksbGUO265Jp3xbMN\n5iEw9CUCgYBmfoPnJwzA5S1zMIqESUdVH6p3UwHU/+XTY6JHAnEVsE+BuLe3ioi7\n6dU4rFd845MCkunBlASLV8MmMbod9xU0vTVHPtmANaUCPxwUIxXQket09t19Dzg7\nA23sE+5myXtcfz6YrPhbLkijV4Nd7fmecodwDckvpBaWTMrv52/Www==\n-----END RSA PRIVATE KEY-----\n"
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/only-2-allowed' } ]
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/allowed' } ]
        - headers: [ { name: ':path', safe_regex_match: { google_re2: {}, regex: '.*public$' } } ]
        - headers: [ { name: ':authority', exact_match: 'allowedHOST' } ]
        - headers: [ { name: ':authority', safe_regex_match: { google_re2: {}, regex: '.*REGEX.*' } } ]
        - headers: [ { name: ':method', exact_match: 'PUT' }, { name: ':path', exact_match: '/public/opinions' } ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/only-2-allowed' } ]
)EOF";

  /*
   * Use filter_chain_match on a requestedServerName that is set by the cilium bpf metadata filter based on the applicable network policy?
   * "example.domain.name.namespace"
   */
class CiliumHttpTLSIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumHttpTLSIntegrationTest(const std::string& config) : CiliumHttpIntegrationTest(config) {}
  ~CiliumHttpTLSIntegrationTest() {}

  void initialize() override {
    CiliumHttpIntegrationTest::initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("http"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    Network::ClientConnectionPtr ssl_client_ =
        dispatcher_->createClientConnection(address, Network::Address::InstanceConstSharedPtr(),
                                            context_->createTransportSocket(nullptr), nullptr);

    ssl_client_->enableHalfClose(true);
    codec_client_ = makeHttpConnection(std::move(ssl_client_));
  }

  void createUpstreams() override {
    if (upstream_tls_) {
      fake_upstreams_.emplace_back(new FakeUpstream(
          createUpstreamSslContext(), 0, FakeHttpConnection::Type::HTTP1, version_, timeSystem(),
          true));
    } else {
      CiliumHttpIntegrationTest::createUpstreams();
    }
  }

  // TODO(mattklein123): This logic is duplicated in various places. Cleanup in a follow up.
  Network::TransportSocketFactoryPtr createUpstreamSslContext() {
    envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext tls_context;
    auto* common_tls_context = tls_context.mutable_common_tls_context();
    auto* tls_cert = common_tls_context->add_tls_certificates();
    tls_cert->mutable_certificate_chain()->set_filename(TestEnvironment::runfilesPath(
        fmt::format("test/config/integration/certs/{}cert.pem", upstream_cert_name_)));
    tls_cert->mutable_private_key()->set_filename(TestEnvironment::runfilesPath(
        fmt::format("test/config/integration/certs/{}key.pem", upstream_cert_name_)));
    ENVOY_LOG_MISC(debug, "Fake Upstream Downstream TLS context: {}", tls_context.DebugString());
    auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static Stats::Scope* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store, std::vector<std::string>{});
  }

  void Denied(Http::TestRequestHeaderMapImpl&& headers) {
    policy_config = TestEnvironment::substitute(BASIC_TLS_POLICY, GetParam());
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    response->waitForEndStream();

    uint64_t status;
    EXPECT_EQ(true, absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
    EXPECT_EQ(403, status);
  }

  void Failed(Http::TestRequestHeaderMapImpl&& headers) {
    policy_config = TestEnvironment::substitute(BASIC_TLS_POLICY, GetParam());
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    response->waitForEndStream();

    uint64_t status;
    EXPECT_EQ(true, absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
    EXPECT_EQ(503, status);
  }

  void Accepted(Http::TestRequestHeaderMapImpl&& headers) {
    policy_config = TestEnvironment::substitute(BASIC_TLS_POLICY, GetParam());
    initialize();
    auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    uint64_t status;
    EXPECT_EQ(true, absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
    EXPECT_EQ(200, status);
  }

  // Upstream
  bool upstream_tls_{true};
  std::string upstream_cert_name_{"upstreamlocalhost"};

  // Downstream
  Network::TransportSocketFactoryPtr context_;
};

class CiliumTLSHttpIntegrationTest : public CiliumHttpTLSIntegrationTest {
public:
  CiliumTLSHttpIntegrationTest()
    : CiliumHttpTLSIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tls_http_proxy_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumTLSHttpIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, InvalidHostNameSNI) {
  // SNI is now coming from the cilium listener filter, so it is accepted
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "nonlocalhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefixStrippedHeader) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "localhost"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "localhost"}});
}

} // namespace Cilium

} // namespace Envoy
