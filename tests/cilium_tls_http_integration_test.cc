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
        typed_config:
          "@type": type.googleapis.com/cilium.DownstreamTlsWrapperContext
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
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUAM3GAjabuMnzR08aU9j8mRwnOGQwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjIwNDA3MTY0\nNjM2WhcNMjQwNDA2MTY0NjM2WjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMSzKRJ0BRNcbgDJ\nvDKGiC+dDTjWCELZmmhuXxGXn4nb9zkPrENul7D64Y/mPEFrAnzvkdbCStRRppqv\nlih9aPBJGnLt/BFnE+1gwSVWHcIuGiscn43FfJQk1x9WzOFuNYRa8qFqiSy2yuBl\nDLsE3GAJwlA3R+H42RroKSgc9QIu0YWOEuFxxwbZ4YludeVn4eZ2UIJc+9IalqQd\n/USNWpDbF15rzTIdHQDkDWiJ7i0P1nQYOg9Ox8Fz4DHvFsZ8pec5ayt90fxQCDBZ\nltqg/XQN6gJTo6Sjt/+hlN8HYa6nPaTomky5p25nW83+1+VY6PXlWxJY5mNtnw2g\nIzH+WQ8CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFHHiOkwR36EVUcLG8EXuMUbnJlgVMB8GA1UdIwQYMBaAFHHiOkwR\n36EVUcLG8EXuMUbnJlgVMA0GCSqGSIb3DQEBCwUAA4IBAQAFPwnsXdW9k2c0bnhU\nQ2L5mC9sMINg5+jlF1vaQC0bedAjkA7b+sNyTyiFFFRZtww+/bRLBDZA71psLp5Y\nUxRIyq0xdoeYx+uauFYnVdHIyuyepXAc2nQaqniVejgD12GMkOrQJfRU0g9PCpwN\nSu9VKJuIsXikGaiCFMMFMEqPrJ89TRXurIQFw2br6fAck0XkAIhRk636SocEinI2\n6KH27rApltg6hY9vP4sSrz+fY46o95v+2P3ef0y9ZG0h+4JkqmcjM3+Od1BehAZQ\n4TC+xARjTmS2jqErZwAdw4ogElvO1w/0mMm7xZZJgqOf6rcdTyeJH0wMZAD1n0Bd\nBxbX\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEhTCCA22gAwIBAgIUT9Wze0Fvw/pMvqAmPJjlD7HNjY4wDQYJKoZIhvcNAQEL\nBQAwdjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxEDAOBgNVBAMMB1Rlc3QgQ0EwHhcNMjIwNDA3MTY0NjM1WhcNMjQw\nNDA2MTY0NjM1WjCBpjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx\nFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsM\nEEx5ZnQgRW5naW5lZXJpbmcxGjAYBgNVBAMMEVRlc3QgQmFja2VuZCBUZWFtMSQw\nIgYJKoZIhvcNAQkBFhViYWNrZW5kLXRlYW1AbHlmdC5jb20wggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQDL/SIbkiu2pqqOBHpOkNMVX9X3DVd6um1ZbByB\n3Ulls8L4+S9IdHl8egst5VEaV+493HsZqItv9gSu4pXQs3Ybgjus+xkc7hzWst5+\n+wkD8T4GH6mKTbfB+U//d535xtRxFK0FMQ5bykTpkic3vzQLjNG2x0SK9BkzsAxR\nfF8mmjd56lxqnB13bs7MBX2MY6aUliOMSd59RsCz7No6L2I280wyl6I/DwTfo8NF\nXO1CIF1NLfnke3HvsKQ1tuvpzCcZVIef7ZOQw4sj4Jo/YD/ocHy5dSmYkCxKyfGL\ncCAEwRuy8qVHdZsGriO3Ql+O3ryLU/ElN6lxV7L4Ol+5n5xvAgMBAAGjgdkwgdYw\nDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIG\nCCsGAQUFBwMBMFoGA1UdEQRTMFGGHnNwaWZmZTovL2x5ZnQuY29tL2JhY2tlbmQt\ndGVhbYYXaHR0cDovL2JhY2tlbmQubHlmdC5jb22CCGx5ZnQuY29tggx3d3cubHlm\ndC5jb20wHQYDVR0OBBYEFHG3ovGrSDcuiv5/7ZnrNSbR+53PMB8GA1UdIwQYMBaA\nFB0NOZh07PtOrAymg6WLcOaPvzKCMA0GCSqGSIb3DQEBCwUAA4IBAQCTCoPBYbgP\nHN9ih7CN1zf+tjWR4Ex2QZV8QQvGCrxsLAYhDlR1OOe6KHJtngyNtxcEEATJL92Q\nfuOSJqmzOMTA6iFBHUjr8IXrpC+7YPCg9meGbmdgcFL0VfI23RVJkLwxMI06TKOM\n/RjBPl8um2Dy6X8te2d61qVkwKt7LHnUpfz7AzpRFEEHdmYZe7Kvg90+VVMi+jWA\n1Cm+PQAczqBFRuw2IVPN0R50S+0SDRSIMJLx+ehSN787GN9p/mMPiXoF/yiD5XDA\nt5/UwUUbIOwrhnzWzSV1veA1efIOXGTXmt+mT7ueWNMIkWUx1ebk7Xn9q3i3Qey0\nxYYobPcy1znA\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy/0iG5IrtqaqjgR6TpDTFV/V9w1XerptWWwcgd1JZbPC+Pkv\nSHR5fHoLLeVRGlfuPdx7GaiLb/YEruKV0LN2G4I7rPsZHO4c1rLefvsJA/E+Bh+p\nik23wflP/3ed+cbUcRStBTEOW8pE6ZInN780C4zRtsdEivQZM7AMUXxfJpo3eepc\napwdd27OzAV9jGOmlJYjjEnefUbAs+zaOi9iNvNMMpeiPw8E36PDRVztQiBdTS35\n5Htx77CkNbbr6cwnGVSHn+2TkMOLI+CaP2A/6HB8uXUpmJAsSsnxi3AgBMEbsvKl\nR3WbBq4jt0Jfjt68i1PxJTepcVey+DpfuZ+cbwIDAQABAoIBAQCke+e9zZ6b+EY8\nn9WzdkoOySkxvbtVRfAYk/lkqfeeH1ZPBjcfOHQhcBOFnYxJLq/3h8pnRSWyUPEz\nx5dAIwVQZzIRaKO2VTZB1Rdd0rRRTnxR2cQOtl4+9faQq3ZhyvbQe/iL4COQ1ke9\nA1HGPNINoi4UMRfO58dOi11Tc3MSHwVvSavEOP5G2a57KpHdMfzgDpPgidSiIl4g\nke4MAHUIrqdKBws3NhEFRe2ICoQgfdjIprIk8yEgW8S5/naHOs+cUvbiYB2ojCdk\nKrBGQ5GcCH4zOFshlI5UGd1vBNVYCC9MhiOFnPbn35XubHaWrlKjviBBkhx/hhES\nPpwrlBxZAoGBAOxxV3ZslpsHpPzi3/IsigE/hfhHqUGXhRu9dZMYbI8WkHCrk6sY\nFRcHDW1KT5KdvnTPAQer87MHWOoELYFjYb+IZSBk7Ayw4V75vfdQWVZAk5/xfM+O\n7vlA9jnmi1GR53MYuKUJ9y24Zo5AUH9BFl5fIQGk6cMUJmdvOLhJt48LAoGBANzc\nlOsR1grG6NJ+J2oJZMe91HF6DWgW3lYT2zp9CnGJSZC2dGRfMtHw30wzN6d3/mYf\nvgGuTg8Ln+hmbm90CNXMf6NaJnv5864pTTsSKLZgEuA41gmVNi2kuDLmTkpgqrNe\nNmp37JNPf35WbrSbZ3vpbirhQyZf0MI5qYw4exatAoGARSOvi7WdJKBLopdFHS/g\n+xR0PHHYEJIaHk58fxL5S64xdoD1oWZdZGpvhrHgKuNtugJ+LpwdmxBe869dDyTc\nhIGB8MMSM3PVs0wcPKGGPi6L/I1FDfyh7MkON0gvHR8pKwLjm38ahIgTlS1BXLTP\nsbDnme97W8wcnsprL5h+0JkCgYAhJcoD7c1eGLRgwyZPN9G0WL1FurfAY45DBP/m\nK1Yh7CTqXzfgyJjsAWbCHP3BWLUJxsHRpsN4Zpo9WwJAH/4jeGm/rowQF1eHUBOT\nRgpuNMUgeedF0Osstogeu4oMh62W9hDcsdsD0O6lm3tKB/jkFAjAzsYxQDgorlbQ\nALoYkQKBgBoK84QH5Zmm7LRWK6r6ncIrgCYqwQDGIKP5IjPH4yrc9UZqKAytSjad\nW/uPVfoy4v9WmvOEIobVQpMWItdJKQTu+Umju5UdxLqRi1S0paILnHf3ehcObkAq\naTmTWC9U/7xjUuHQwPLdny+6MsZkbigtbF8983DwjePPIJfJ0tQ4\n-----END RSA PRIVATE KEY-----\n"
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

  std::string testPolicyFmt() override {
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
