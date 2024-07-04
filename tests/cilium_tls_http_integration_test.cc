#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/ssl_socket.h"

#include "test/integration/ssl_utility.h"

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
      inline_string: "-----BEGIN CERTIFICATE-----\nMIIEhTCCA22gAwIBAgIUQRkh3sY/JN5+tu5NX3Tbyx0Y8l8wDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjQwNDA4MTA0MjUzWhcNMjYw\nNDA4MTA0MjUzWjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQCqoyXM9pY5gDpLVap5mr0NtQjqCvh+GXZyP7BP\nP2S+oNtSaLLAe5+yNDJoldZSplLGYwrWWJtjWJedeQ5JnhpbFVKrGXDIBtQ/6B/v\noKEkdh3BOB79IKhbmNQTA9pFV+xypvM+IWFr4p5bvjTRgncdXdlzEf6g5ECNdgdi\nhlpdL3aAY/Ko6cEWAzaxypJAumzsaw4HX1HiBP7rhHHZrLsIPc6MZ/LhKztIgJIO\n3U2VOE4uRbcf1uBEkE6H63PKGBnuHJ5qkmLS6IoF9sl7pvydLj5tp1FB8twQMxwP\nWGRTZkpQ121zH5aBIEL1C/1WHgZ6AROEKvMK408e9fiAEfPLAgMBAAGjgdkwgdYw\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMFoGA1UdEQRTMFGGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYYXaHR0cDovL2JhY2tlbmQubHlmdC5jb22CCGx5ZnQuY29tggx3d3cubHlm\ndC5jb20wHQYDVR0OBBYEFF+sq41Nw9S3XL1yJQ51PLCa+mwUMB8GA1UdIwQYMBaA\nFBn+c0Qg6qbDyfGRTNk1jzuKuSOAMA0GCSqGSIb3DQEBCwUAA4IBAQB56Z7/YUQ6\nSkazZPO2Eodg/4eKHQPEluzbz13/wkTBMTewgLgXRCVow8025yt0NaQ9AQzrKELc\nWBD+BuoTA8koD52zXmG9kjpIzajIqv2urWIaH1vUzfM26uJgiQKXX3eo24fbGRQi\nW452PvGPYoGAtucrEg15MrGlfqLMPkNIJ3ufIWRh+ycriWb8kHe+TgB6XQQGhHdJ\nD0+MXSOkPoNM7I8hU2PNl29krHTl3npYK0zG4AOF6tbOuu6bta94kV8PQ4YBfojF\no8vYmMboYDfZnnh+92WT4Ra/BSIm/NXilo3mXOu+cuRP6Kl3kpJPT0zZIjI5DBLn\nQmJKb8oDcA7+\n-----END CERTIFICATE-----\n"
    private_key:
      inline_string: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAqqMlzPaWOYA6S1WqeZq9DbUI6gr4fhl2cj+wTz9kvqDbUmiy\nwHufsjQyaJXWUqZSxmMK1libY1iXnXkOSZ4aWxVSqxlwyAbUP+gf76ChJHYdwTge\n/SCoW5jUEwPaRVfscqbzPiFha+KeW7400YJ3HV3ZcxH+oORAjXYHYoZaXS92gGPy\nqOnBFgM2scqSQLps7GsOB19R4gT+64Rx2ay7CD3OjGfy4Ss7SICSDt1NlThOLkW3\nH9bgRJBOh+tzyhgZ7hyeapJi0uiKBfbJe6b8nS4+badRQfLcEDMcD1hkU2ZKUNdt\ncx+WgSBC9Qv9Vh4GegEThCrzCuNPHvX4gBHzywIDAQABAoIBAQCpC+QBADGnWY9m\n3sF6o3+zuqvQIXo4gsVDPjFO8UC/UeC17Z9Y7aAyDV/7GKYxTzEl9SzhWProGvZp\nPWqYKBd4MNGrTBLdN1bC0RYCcaHy20lzCEQ7BUWFKQzAocp1dDt9AkRsQume1e2I\nehEdliCnaThptWQKxNXmzw1V4EBZm3Jf18azA82Op5O8uD8B7pLdM7cfXVfY5HIL\nN9HFY5yLJwM+N3M447StKQhfwohLtCuB8dVnYgVNKkqYfPyRSYT6h4OFJI+i1BRu\nyzEZoSVfa7oKAEStVH3G76M4TzKL5msU7AJrIogWFNYIy1jWEMJsCmhD5dbQhbJD\n9q1SgkIBAoGBAOJFaRl2PL7yf9RPh0E4iAJmqz9LxTk9PCa1Lu/EdtUdnqumPfVD\nfbsLxLUMYA5qQP411t+fFEgt2eBYj57WWhh035WhCpvhFhLgFqfXyFosI5Ku9xfE\nsOoCxzGOdCVfSi5PqL+cB49H6Msc5R0Wm1nr6Xz9vuW+U8AlxwdYSdNLAoGBAMEO\ngLej7FqBnnySXfTINFpXatPq4EaoMKqqI5Yjy0PlzBWbQtFV01zjo9xH9eCNRxrj\n1mz5tV3i1zyYapULL8hQ/qYVryf/sc4QGqEi2PPmk6KlR1729MMH83dWhuGgojyf\nkPy/+f5vqklRqQa90g01mea7O8mU10cUNmem85GBAoGBAMikiBfd8uvXmWaoxuUc\nve5zIDNWeyLQnAAu9doDOuSsCUFoftR37ovoWZu5x4vAyLUjBNDy/Ucr8WGw5loQ\n9X9uU70ZOpETPUGrmCtpeu4K6dhucgmPjtlTcVMOYQuqvdrnJFoUf9ecCl/h1YC/\nxS4ttbPyRk7vQNDILv7iWUSVAoGAK51xKwvXm+LowU/39hM88KQLOHE51fytcgEa\nJRNVGrPR1ZfMEqsHI1cyb9O6Es8YH1UV3mzTsrBK3B+7BI0QcHsL7M29UpYLv3gX\n7AuJZCDVfctFQokcZutm77EWq+a0gGm0QcXFXtwvZn0SaLl9uQpBCMWIDlSYBjDk\n0aoAIQECgYAfqxwy93/9Ib3hCT8Agft0vxYaycjyWtiu5Aw2hc2tKytWq+Lgi5Eb\npPSL18rxamvxMIJlERCmaoqJmDuNvGPtpv8TLlAz19ZEfrEIQs6J6k0G716cvZxE\nf4soMOrYismLOdHXsliIhvf4iHGnSMbIiN7jyjochK+maHTBE0GlOA==\n-----END RSA PRIVATE KEY-----\n"
)EOF";

// trusted_ca from test/config/integration/certs/upstreamcacert.pem
const std::string CA_CERTS_CONFIG = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: ca-certs
  validation_context:
    trusted_ca:
      inline_string: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUfXpfjZAzA9sFKKe0k9M1rCGG9rwwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjQwNDA4MTA0\nMjUzWhcNMjYwNDA4MTA0MjUzWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQ5VS5O8LtJdNY7\nL9sqH6vVhr9wyHsb7bvBSmg9JAxTU8vSFG/Uj4zoJDBYtEivU9F7leeqcqVLU9MA\n2vvYt/LS7/j2HOU0AfilbIGRJiho24AMlrkgXQSweVD+Y46hH42xythcZhwYS6JQ\nMpe0jkSk8SDUZTCCFeosbt8yTxOILgNsFUgUJ1pkUFyQQDSW+cYfruXgg/U/BdP2\nbme/E6Wf41KhZIZJTGzbxmgRrmF29ktOSwLyJcKpMCVNFforIBOKnF7ANKirnAS4\nFuBx6Q4peQ6/qwmXcucBD4X+YBoTi6+CZejW9LHcZX4gFjWKFlny4QJKxz2eFS+1\neudq86kCAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFHrsizu33Ld1ed/tUUow717Z5RCDMB8GA1UdIwQYMBaAFHrsizu3\n3Ld1ed/tUUow717Z5RCDMA0GCSqGSIb3DQEBCwUAA4IBAQCPlwh6v03l09vHYA8k\nFX0YVZDUKOcz8wtoRHwkTjetGRaDF2xEu2NGr/RHFS5EyJ9kuwgc1nOGS8lfqDk9\nCznok/2qsN+ctp571ufhK+EZf5FI9etQJP1f0YleXrP3KR3ztQ5zLGXCv6E0oqXi\n6ct4FZJwq5RdP4LYJUWCfCAf5z8Yr6nLUlXTW2Kwwi3+3isqc97jdRMkL37Y3CyR\nEgAHSbw26XozFmY+K7ptspwb8zPaWKMUDNSGJVnfCqo8ABWJbDcdRa/AZA4KXScP\nH/A2sZtKx8b3mOIu/uX5NQCO+e0Tvm6qqCSGr+Ykcn7HI6Rr43d19He/zn82oHZF\nqhaf\n-----END CERTIFICATE-----\n"
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
  ~CiliumHttpTLSIntegrationTest() {}

  void initialize() override {
    CiliumHttpIntegrationTest::initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the SSL client.
    Network::Address::InstanceConstSharedPtr address =
        Ssl::getSslAddress(version_, lookupPort("http"));
    context_ = createClientSslTransportSocketFactory(context_manager_, *api_);
    Network::ClientConnectionPtr ssl_client_ = dispatcher_->createClientConnection(
        address, Network::Address::InstanceConstSharedPtr(),
        context_->createTransportSocket(nullptr, nullptr), nullptr, nullptr);

    ssl_client_->enableHalfClose(true);
    codec_client_ = makeHttpConnection(std::move(ssl_client_));
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
    auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static auto* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store->rootScope(),
        std::vector<std::string>{});
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
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "localhost"}});
}

TEST_P(CiliumTLSHttpIntegrationTest, AllowedPathPrefixStrippedHeader) {
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "localhost"},
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
