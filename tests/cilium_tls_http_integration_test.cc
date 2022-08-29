#include "source/extensions/transport_sockets/tls/context_config_impl.h"
#include "source/extensions/transport_sockets/tls/ssl_socket.h"
#include "test/integration/ssl_utility.h"
#include "tests/bpf_metadata.h"  // policy_config
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
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
    - filters:
      - name: cilium.network
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
)EOF";

// upstream_tls_context tructed_ca from
// test/config/integration/certs/upstreamcacert.pem downstream_tls_context
// certificate_chain from test/config/integration/certs/servercert.pem
// downstream_tls_context private_key from
// test/config/integration/certs/serverkey.pem
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
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUHkFr63OMk16jo5MPoqK3PlULtekwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjIwODI0MTcz\nNjMwWhcNMjQwODIzMTczNjMwWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALk8BA8Cs01sBw3j\nD2i599YAzh94DqsOK0KZSVBi6OxgYbxPSgeieDACEx67QYVesXw/kDAhSIeAvQVX\n1KP11clF3voW4Y+E1X8uVGc0VCNJ4UzKCU65L0ZPwiD2ZFHQKBScPJCT50mqbb/1\nybPpK0kuv037j9++lmBlY+c1NIZw/6UZyLDkPsZS7vv1gXi2o+5mP9u/mrbFuu3f\nbey6BcCVSP/8ivPHoSHsrNC4NaG9IpB0JpdvpKLMw2OYv23WMKX68ZQzi/h1jt8q\nneZb5Bigb2jNcNuRtjFyVLVgQQVRFYk98YwunhByPnkG3FayYg0+wrhjZhk3rQk7\n6N92YHUCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFACFVv61b2bdtoJmP5hcuLKaCQkkMB8GA1UdIwQYMBaAFACFVv61\nb2bdtoJmP5hcuLKaCQkkMA0GCSqGSIb3DQEBCwUAA4IBAQBbvvfEsLdPKJ/UpHbC\n97rAHRYEHZaaAiFmq3UCTUlQi/Lcy9N3ly3S93iwSMgoWvWM8T7QHgrxASSNC+I+\nw0BRMUxaXrrQi2uBfLIdqyZsQGOjRNzbRkY/zhpT1lYS98e4KxCDsnbiXPCaAoid\n+iFo2ZcXHp2dAAX4WSov+XWkj8gLV5/BuU3PBYGb22NTvZ9OFR+a4dy0Ho/HKvHm\nJhjZCOBCsT1ByWK8QYgCyQTvyU9jqSnvgqVla/WpoVN6ElUNseKcBVsWmLMRYeSd\nE22WZUHIH6fFXvW5iCXHHKIU1YLVsqEYTuzgeNyiaK4LB53k3aSdrMMbnwlnXnga\nyLTR\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEbDCCA1SgAwIBAgIUR+PIa0zfnk5rFmwbOHhyMO78/dMwDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjIwODI0MTczNjMwWhcNMjQw\nODIzMTczNjMwWjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDAnh6X9VR07QpY6DdDhtpEYdvgzlWQtcbF7hLG\nSZfI96g4UYmd+/MLUCp8qEVQLj3tXzNA4GOtvYyt5b2AoBeGlOVqYOAOzE5v4m2B\nwaTV+BE8wPakN5QvY/4d9QWhUlaoOpc9v2wBOCo1IWydCERUDzsKBTii/fc4QMLU\n2k5Tlf4GdD8Gv3SwNtlomAVGYLqCGrSDM2pidcwFHFfhl7q5vQCYDJBUTj+ZAQ5u\ntK8XctT1SyTsMdvLdvsyEliVSQLx6fiaWZFoqzG1MABYl1bGHDIExofV3XF5vgUY\n34GnGXU/GuEd6KgnZ332cuRPPza2QhgOhI1dSUkQWJJuxMhVAgMBAAGjgcAwgb0w\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMEEGA1UdEQQ6MDiGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYIIbHlmdC5jb22CDHd3dy5seWZ0LmNvbTAdBgNVHQ4EFgQUZ43tuRh7QSIn\nH4BX7ixJ+OpnkdswHwYDVR0jBBgwFoAUtYfqLVoudk3cWmthuqrrQ8oHDYkwDQYJ\nKoZIhvcNAQELBQADggEBAAfOe1LuEAbsNSXV8PoVJ2Yn70Q0xlY4JRdlS0PxeFI6\nJSr3jxdC1JJc49FIw1yiPmGDr6qa08wAU4nG248OIbxhStLjWk/d6osVoorLyehU\nwniVNzd4rFBoVWOje6Wvt9Kuf7psUpYjlidKfbWJDIU3rg3y8q75xWuPwS946EXK\neVOJnC4zDTNUG+WF4rj+cCEylzy4qTKsclnI49cInnQGS8X0MN1mFQCYQ+7VQFDs\nd3G+ekmjTZdmamLN38lb/sxCgQS1TSHQf/+38v6Jb4wjb+q5lr6sUc3Cl+D00BTc\nM7etRVBv8cpouWRRaBX92s4/iID1V8ZlepoY9sCnq1Y=\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpgIBAAKCAQEAwJ4el/VUdO0KWOg3Q4baRGHb4M5VkLXGxe4SxkmXyPeoOFGJ\nnfvzC1AqfKhFUC497V8zQOBjrb2MreW9gKAXhpTlamDgDsxOb+JtgcGk1fgRPMD2\npDeUL2P+HfUFoVJWqDqXPb9sATgqNSFsnQhEVA87CgU4ov33OEDC1NpOU5X+BnQ/\nBr90sDbZaJgFRmC6ghq0gzNqYnXMBRxX4Ze6ub0AmAyQVE4/mQEObrSvF3LU9Usk\n7DHby3b7MhJYlUkC8en4mlmRaKsxtTAAWJdWxhwyBMaH1d1xeb4FGN+Bpxl1Pxrh\nHeioJ2d99nLkTz82tkIYDoSNXUlJEFiSbsTIVQIDAQABAoIBAQCsxSdr5gH7XyMI\n3EG1sB/Xdm9jFbBqPKIup3zvntMmz/1zhq+JpZQ7cYyqg8SoRtIFOH8gkiTWkk69\nLHTuCqsPbD7bTEms/FTexpqy6J6RzhCoDe0tHy0r1OT6uexy5wgTnXpLSIf4EAjL\n308tC10+iOrL8iL7EBHPw0b+5VGcZj4M34QMXQyIAOZMBPaeGef+RMGVaQnqbg1A\nJt1VBAmencE39ThqwK/31dAcHjxhC8iVzQyrz3u2L/uIX9f2BVCvvwwMGVyip73r\nJczqAQrvxobJR14dw5BFg5fnroG1v70sOZdJgxJvqeVuAENsdsR5STjf7AnNeHpv\nw1FJVcABAoGBAO+5VKGyxS3UgpJvWLKkMGLl6i1g2ClbTzqv/Gc/Ef4bgXS9ZqVo\nIEOqnqY9SRvKVomCAivID1HygOf4z9TC0QX8DXtxrtUYZWccD9lcsoO+rSAeWx4/\npLVz8K7GQr9oYk1sqSRHK+XBZz3i07Q8oxmQi8b/5E63VN/lhW23vHWBAoGBAM2y\nB26XbAYI79wrXfhRAr7ogIURugUooaggFM1lMvbbqD75NYYqx/9O7x+mI7MT8Dc8\nkAjrbt+qyG2PitcQE58UuuwJ/BUaCx6MbYfEyWtGEZoffpyRwT5sAQzVBe7SJkfS\nfAjqIfNe6OK+CAxXelDHcl7QT8sCenA9FyU3oQTVAoGBANoNHeonDivtzQcduPRl\nXI3Yy/WSzYxwvdSIF3JicB9PLaXeUevKlu511/EmdcWNesGBPDBOvYCwsIhQTdsd\nibuD1U+fzIOQuUvcvp3cL5SecCNy+Ta+dTeHyjlvpW8tp5z9ZazWABvwm9Qy6pZb\nQZATZtEQGb9wCwfNYly2b/oBAoGBAL3ccde2lNMNNLj4nogx3mLwoJAzSIyycGSL\nGChuHJiXL7jQtoLcwjX6WeXQqGsHIFcb46cYCQMS1GWsdO8Fu9a+f7qXjMK9gz3z\nSLZlAbWuu1iTcX57Wu+PKXj6t7s05nis5CgmVKgbFsMTvMIHjLM7JWo2xTARXYp0\nGQUVT97xAoGBALv5kdsaHqZ+/Obn8qx2yGktnwWk/xgh40GWC1PSbIvfS+Bpvqs9\n5tCM/V9u/s5ejI3CSvl0iLuozLnm4H8gFkaymujtnojNOhOyzYAY4KsdmCnfsbtc\n/98b/vAZQZl5EvkxSwE4WmmTwnT1VFlmKZjKK7io/5z7tjh39MaHkvAD\n-----END RSA PRIVATE KEY-----\n"
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
  CiliumHttpTLSIntegrationTest(const std::string& config)
      : CiliumHttpIntegrationTest(config) {}
  ~CiliumHttpTLSIntegrationTest() {}

  void initialize() override {
    CiliumHttpIntegrationTest::initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("http"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    Network::ClientConnectionPtr ssl_client_ =
        dispatcher_->createClientConnection(
            address, Network::Address::InstanceConstSharedPtr(),
            context_->createTransportSocket(nullptr), nullptr);

    ssl_client_->enableHalfClose(true);
    codec_client_ = makeHttpConnection(std::move(ssl_client_));
  }

  void createUpstreams() override {
    if (upstream_tls_) {
      auto config = upstreamConfig();
      config.upstream_protocol_ = FakeHttpConnection::Type::HTTP1;
      config.enable_half_close_ = true;
      fake_upstreams_.emplace_back(new FakeUpstream(createUpstreamSslContext(), 0, version_, config));
    } else {
      CiliumHttpIntegrationTest::createUpstreams();
    }
  }

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
    ENVOY_LOG_MISC(debug, "Fake Upstream Downstream TLS context: {}",
                   tls_context.DebugString());
    auto cfg = std::make_unique<
        Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static Stats::Scope* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<
        Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store,
        std::vector<std::string>{});
  }

  std::string testPolicyFmt() {
    return TestEnvironment::substitute(BASIC_TLS_POLICY_fmt, GetParam());
  }

  void Denied(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("403", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }

  void Failed(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("503", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }

  void Accepted(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    auto response =
        sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

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
  Network::TransportSocketFactoryPtr context_;
};

class CiliumTLSHttpIntegrationTest : public CiliumHttpTLSIntegrationTest {
 public:
  CiliumTLSHttpIntegrationTest()
      : CiliumHttpTLSIntegrationTest(
            fmt::format(TestEnvironment::substitute(
                            cilium_tls_http_proxy_config_fmt, GetParam()),
                        "true")) {}
};

INSTANTIATE_TEST_SUITE_P(
    IpVersions, CiliumTLSHttpIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPathPrefix) {
  Denied(
      {{":method", "GET"}, {":path", "/prefix"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefix) {
  Accepted(
      {{":method", "GET"}, {":path", "/allowed"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefixStrippedHeader) {
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "localhost"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathRegex) {
  Accepted({{":method", "GET"},
            {":path", "/maybe/public"},
            {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"},
          {":path", "/maybe/private"},
          {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"},
          {":path", "/maybe/private"},
          {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"},
            {":path", "/public/opinions"},
            {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"},
          {":path", "/only-2-allowed"},
          {":authority", "localhost"}});
}

}  // namespace Cilium

}  // namespace Envoy
