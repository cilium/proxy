#include "source/common/config/decoded_resource_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/thread_local/thread_local_impl.h"

#include "cilium/secret_watcher.h"
#include "tests/bpf_metadata.h" // host_map_config
#include "tests/cilium_http_integration.h"

namespace Envoy {

// params: destination port number
const std::string BASIC_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*public$'
        - headers:
          - name: ':authority'
            exact_match: 'allowedHOST'
        - headers:
          - name: ':authority'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*REGEX.*'
        - headers:
          - name: ':method'
            exact_match: 'PUT'
          - name: ':path'
            exact_match: '/public/opinions'
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/only-2-allowed'
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*public$'
        - headers:
          - name: ':authority'
            exact_match: 'allowedHOST'
        - headers:
          - name: ':authority'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*REGEX.*'
        - headers:
          - name: ':method'
            exact_match: 'PUT'
          - name: ':path'
            exact_match: '/public/opinions'
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/only-2-allowed'
)EOF";

const std::string SECRET_TOKEN_CONFIG = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: bearer-token
  generic_secret:
    secret:
      inline_string: "d4ef0f5011f163ac"
)EOF";

const std::string HEADER_ACTION_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
          header_matches:
          - name: 'header42'
            match_action: FAIL_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
          - name: 'bearer-token'
            value_sds_secret: 'bearer-token'
            mismatch_action: REPLACE_ON_MISMATCH
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*public$'
          header_matches:
          - name: 'user-agent'
            value: 'CuRL'
            mismatch_action: DELETE_ON_MISMATCH
        - headers:
          - name: ':authority'
            exact_match: 'allowedHOST'
          header_matches:
          - name: 'header2'
            value: 'value2'
            mismatch_action: ADD_ON_MISMATCH
          - name: 'header42'
            match_action: DELETE_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
        - headers:
          - name: ':authority'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*REGEX.*'
          header_matches:
          - name: 'header42'
            value: '42'
            mismatch_action: DELETE_ON_MISMATCH
        - headers:
          - name: ':method'
            exact_match: 'PUT'
          - name: ':path'
            exact_match: '/public/opinions'
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/only-2-allowed'
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
          header_matches:
          - name: 'header42'
            match_action: FAIL_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
          - name: 'bearer-token'
            value_sds_secret: 'bearer-token'
            mismatch_action: REPLACE_ON_MISMATCH
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*public$'
          header_matches:
          - name: 'user-agent'
            value: 'CuRL'
            mismatch_action: DELETE_ON_MISMATCH
        - headers:
          - name: ':authority'
            exact_match: 'allowedHOST'
          header_matches:
          - name: 'header2'
            value: 'value2'
            mismatch_action: ADD_ON_MISMATCH
          - name: 'header42'
            match_action: DELETE_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
        - headers:
          - name: ':authority'
            safe_regex_match:
              google_re2: {{}}
              regex: '.*REGEX.*'
          header_matches:
          - name: 'header42'
            value: '42'
            mismatch_action: DELETE_ON_MISMATCH
        - headers:
          - name: ':method'
            exact_match: 'PUT'
          - name: ':path'
            exact_match: '/public/opinions'
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/only-2-allowed'
)EOF";

// params: is_ingress ("true", "false")
const std::string cilium_upstream_config_fmt = R"EOF(
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
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        common_http_protocol_options:
          max_requests_per_connection: 3
        use_downstream_protocol_config: {{}}
        http_filters:
        - name: test_l7policy
          typed_config:
            "@type": type.googleapis.com/cilium.L7Policy
            access_log_path: "{{ test_udsdir }}/access_log.sock"
        - name: envoy.filters.http.upstream_codec
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.upstream_codec.v3.UpstreamCodec
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
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.TestBpfMetadata
        is_ingress: {0}
        is_l7lb: true
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: envoy.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: config_test
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
                  cluster: cluster1
                  max_grpc_timeout:
                    seconds: 0
                    nanos: 0
                match:
                  prefix: "/"
)EOF";

class CiliumIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumIntegrationTest()
      : CiliumHttpIntegrationTest(fmt::format(
            TestEnvironment::substitute(cilium_upstream_config_fmt, GetParam()), "false")) {
    host_map_config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::/104" ]
)EOF";
  }
  CiliumIntegrationTest(const std::string& config) : CiliumHttpIntegrationTest(config) {}

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(HEADER_ACTION_POLICY_fmt, GetParam());
  }

  std::vector<std::pair<std::string, std::string>> testSecrets() override {
    return std::vector<std::pair<std::string, std::string>>{
        {"bearer-token", SECRET_TOKEN_CONFIG},
    };
  }

  void initialize() override {
    accessLogServer_.clear();
    if (!initialized_) {
      HttpIntegrationTest::initialize();
      initialized_ = true;
    }
  }

  void Denied(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    ASSERT_TRUE(response->waitForEndStream());

    // Validate that request access log message with x-request-id is logged
    absl::optional<std::string> maybe_x_request_id;
    EXPECT_TRUE(expectAccessLogDeniedTo([&maybe_x_request_id](const ::cilium::LogEntry& entry) {
      maybe_x_request_id = getHeader(entry.http().headers(), "x-request-id");
      return entry.http().status() == 0;
    }));
    ASSERT_TRUE(maybe_x_request_id.has_value());

    // Validate that response x-request-id is the same as in request
    absl::optional<std::string> maybe_x_request_id_resp;
    EXPECT_TRUE(
        expectAccessLogResponseTo([&maybe_x_request_id_resp](const ::cilium::LogEntry& entry) {
          maybe_x_request_id_resp = getHeader(entry.http().headers(), "x-request-id");
          return entry.http().status() == 403;
        }));
    ASSERT_TRUE(maybe_x_request_id_resp.has_value());
    EXPECT_EQ(maybe_x_request_id.value(), maybe_x_request_id_resp.value());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("403", response->headers().getStatusValue());
    cleanupUpstreamAndDownstream();
  }

  void Accepted(Http::TestRequestHeaderMapImpl&& headers) {
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    // Validate that request access log message with x-request-id is logged
    absl::optional<std::string> maybe_x_request_id;
    EXPECT_TRUE(expectAccessLogRequestTo([&maybe_x_request_id](const ::cilium::LogEntry& entry) {
      maybe_x_request_id = getHeader(entry.http().headers(), "x-request-id");
      return entry.http().status() == 0;
    }));
    ASSERT_TRUE(maybe_x_request_id.has_value());

    // Validate that response x-request-id is the same as in request
    absl::optional<std::string> maybe_x_request_id_resp;
    EXPECT_TRUE(
        expectAccessLogResponseTo([&maybe_x_request_id_resp](const ::cilium::LogEntry& entry) {
          maybe_x_request_id_resp = getHeader(entry.http().headers(), "x-request-id");
          return entry.http().status() == 200;
        }));
    ASSERT_TRUE(maybe_x_request_id_resp.has_value());
    EXPECT_EQ(maybe_x_request_id.value(), maybe_x_request_id_resp.value());

    EXPECT_TRUE(response->complete());
    EXPECT_EQ("200", response->headers().getStatusValue());
    EXPECT_TRUE(upstream_request_->complete());
    EXPECT_EQ(0, upstream_request_->bodyLength());
    cleanupUpstreamAndDownstream();
  }

  bool initialized_ = false;
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "host"},
            {"bearer-token", "d4ef0f5011f163ac"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    return http.missing_headers_size() == 1 && hasHeader(missing, "header42") &&
           http.rejected_headers_size() == 0 && !hasHeader(http.headers(), "header42");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefixWrongHeader) {
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "host"},
            {"bearer-token", "wrong-value"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& rejected = http.rejected_headers();
    const auto& missing = http.missing_headers();
    return http.rejected_headers_size() == 1 && hasHeader(rejected, "bearer-token", "[redacted]") &&
           http.missing_headers_size() == 2 && hasHeader(missing, "header42") &&
           hasHeader(missing, "bearer-token", "[redacted]") &&
           // Check that logged headers have the replaced value
           hasHeader(http.headers(), "bearer-token", "d4ef0f5011f163ac") &&
           !hasHeader(http.headers(), "header42");
  }));
}

TEST_P(CiliumIntegrationTest, MultipleRequests) {
  // 1st request
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "host"},
            {"bearer-token", "d4ef0f5011f163ac"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    return http.missing_headers_size() == 1 && hasHeader(missing, "header42") &&
           http.rejected_headers_size() == 0 && !hasHeader(http.headers(), "header42");
  }));

  // 2nd request
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "host"},
            {"bearer-token", "wrong-value"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& rejected = http.rejected_headers();
    const auto& missing = http.missing_headers();
    return http.rejected_headers_size() == 1 && hasHeader(rejected, "bearer-token", "[redacted]") &&
           http.missing_headers_size() == 2 && hasHeader(missing, "header42") &&
           hasHeader(missing, "bearer-token", "[redacted]") &&
           // Check that logged headers have the replaced value
           hasHeader(http.headers(), "bearer-token", "d4ef0f5011f163ac") &&
           !hasHeader(http.headers(), "header42");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, AllowedPathRegexDeleteHeader) {
  Accepted({{":method", "GET"},
            {":path", "/maybe/public"},
            {":authority", "host"},
            {"User-Agent", "test"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& rejected = http.rejected_headers();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 1 &&
           hasHeader(rejected, "user-agent", "test") && !hasHeader(http.headers(), "User-Agent");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedHostRegexDeleteHeader) {
  Accepted({{":method", "GET"},
            {":path", "/maybe/private"},
            {":authority", "hostREGEXname"},
            {"header42", "test"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& rejected = http.rejected_headers();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 1 &&
           hasHeader(rejected, "header42", "test") &&
           !hasHeader(http.headers(), "header42", "test");
  }));
}

TEST_P(CiliumIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, AllowedHostString) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "allowedHOST"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    return http.missing_headers_size() == 2 && hasHeader(missing, "header2", "value2") &&
           hasHeader(missing, "header42") && http.rejected_headers_size() == 0 &&
           !hasHeader(http.headers(), "header42") && hasHeader(http.headers(), "header2", "value2");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedReplaced) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "allowedHOST"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    return http.missing_headers_size() == 3 && hasHeader(missing, "bearer-token", "[redacted]") &&
           hasHeader(missing, "header2", "value2") && hasHeader(missing, "header42") &&
           http.rejected_headers_size() == 0 && !hasHeader(http.headers(), "header42") &&
           hasHeader(http.headers(), "header2", "value2") &&
           hasHeader(http.headers(), "bearer-token", "d4ef0f5011f163ac");
  }));
}

TEST_P(CiliumIntegrationTest, Denied42) {
  Denied({{":method", "GET"},
          {":path", "/allowed"},
          {":authority", "host"},
          {"header42", "anything"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    const auto& rejected = http.rejected_headers();
    return http.rejected_headers_size() == 1 && hasHeader(rejected, "header42") &&
           http.missing_headers_size() == 1 && hasHeader(missing, "bearer-token", "[redacted]") &&
           hasHeader(http.headers(), "header42") &&
           hasHeader(http.headers(), "bearer-token", "d4ef0f5011f163ac");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedReplacedAndDeleted) {
  Accepted({{":method", "GET"},
            {":path", "/allowed"},
            {":authority", "allowedHOST"},
            {"header42", "anything"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    const auto& rejected = http.rejected_headers();
    return http.rejected_headers_size() == 1 && hasHeader(rejected, "header42") &&
           http.missing_headers_size() == 2 && hasHeader(missing, "bearer-token", "[redacted]") &&
           hasHeader(missing, "header2", "value2") && !hasHeader(http.headers(), "header42") &&
           hasHeader(http.headers(), "header2", "value2") &&
           hasHeader(http.headers(), "bearer-token", "d4ef0f5011f163ac");
  }));
}

TEST_P(CiliumIntegrationTest, AllowedHostRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

TEST_P(CiliumIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    const auto& http = entry.http();
    return http.missing_headers_size() == 0 && http.rejected_headers_size() == 0;
  }));
}

class CiliumIntegrationEgressTest : public CiliumIntegrationTest {
public:
  CiliumIntegrationEgressTest()
      : CiliumIntegrationTest(fmt::format(
            TestEnvironment::substitute(cilium_upstream_config_fmt, GetParam()), "false")) {
    host_map_config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::/104" ]
)EOF";
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumIntegrationEgressTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationEgressTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedHostString) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedHostRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}});
}

TEST_P(CiliumIntegrationEgressTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "host"}});
}

const std::string L34_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  egress_per_port_policies:
  - port: {0}
    end_port: {0}
    rules:
    - remote_policies: [ 42 ]
)EOF";

class CiliumIntegrationEgressL34Test : public CiliumIntegrationEgressTest {
public:
  CiliumIntegrationEgressL34Test() {}

  std::string testPolicyFmt() { return TestEnvironment::substitute(L34_POLICY_fmt, GetParam()); }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, CiliumIntegrationEgressL34Test,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationEgressL34Test, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressL34Test, DeniedPathPrefix2) {
  Denied({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});
}

const std::string HEADER_ACTION_MISSING_SDS_POLICY_fmt = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed2'
    - remote_policies: [ 42 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/only42'
)EOF";

const std::string HEADER_ACTION_MISSING_SDS_POLICY2_fmt = R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
          header_matches:
          - name: 'header42'
            match_action: FAIL_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
          - name: 'bearer-token'
            value_sds_secret: 'nonexisting-sds-secret'
            mismatch_action: REPLACE_ON_MISMATCH
)EOF";

class SDSIntegrationTest : public CiliumIntegrationTest {
public:
  SDSIntegrationTest() : CiliumIntegrationTest() {
    // switch back to SDS secrets so that we can test with a missing secret.
    // File based secret fails if the file does not exist, while SDS should allow for secret to be
    // created in future.
    Cilium::resetSDSConfigFunc();

    host_map_config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 42
  host_addresses: [ "192.168.1.1", "f00d::1:1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::/104" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 2
  host_addresses: [ "0.0.0.0/0", "::/0" ]
)EOF";
  }

  std::string testPolicyFmt2() {
    return TestEnvironment::substitute(HEADER_ACTION_MISSING_SDS_POLICY2_fmt, GetParam());
  }

  std::string testPolicyFmt() override {
    return TestEnvironment::substitute(HEADER_ACTION_MISSING_SDS_POLICY_fmt, GetParam());
  }

  std::vector<std::pair<std::string, std::string>> testSecrets() override {
    return std::vector<std::pair<std::string, std::string>>{}; // No secrets
  }
};

INSTANTIATE_TEST_SUITE_P(IpVersions, SDSIntegrationTest,
                         testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(SDSIntegrationTest, TestDeniedL3) {
  Denied({{":method", "GET"}, {":path", "/only42"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    auto source_ip = Network::Utility::parseInternetAddressAndPort(entry.source_address())
                         ->ip()
                         ->addressAsString();
    const auto& http = entry.http();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 0 &&
           entry.destination_security_id() == 1 &&
           source_ip == ((GetParam() == Network::Address::IpVersion::v4) ? "127.0.0.1" : "::1");
  }));
}

TEST_P(SDSIntegrationTest, TestDeniedL3SpoofedXFF) {
  Denied({{":method", "GET"},
          {":path", "/only42"},
          {":authority", "host"},
          {"x-forwarded-for", "192.168.1.1"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    auto source_ip = Network::Utility::parseInternetAddressAndPort(entry.source_address())
                         ->ip()
                         ->addressAsString();
    const auto& http = entry.http();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 0 &&
           entry.destination_security_id() == 1 &&
           source_ip == ((GetParam() == Network::Address::IpVersion::v4) ? "127.0.0.1" : "::1");
  }));
}

TEST_P(SDSIntegrationTest, TestMissingSDSSecretOnUpdate) {
  Accepted({{":method", "GET"}, {":path", "/allowed2"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    auto source_ip = Network::Utility::parseInternetAddressAndPort(entry.source_address())
                         ->ip()
                         ->addressAsString();
    const auto& http = entry.http();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 0;
  }));

  // Update policy that still has the missing secret
  auto port = fake_upstreams_[0]->localAddress()->ip()->port();
  auto config = fmt::format(testPolicyFmt2(), port);
  std::string temp_path =
      TestEnvironment::writeStringToFileForTest("network_policy_tmp.yaml", config);
  std::string backup_path = policy_path + ".backup";
  TestEnvironment::renameFile(policy_path, backup_path);
  TestEnvironment::renameFile(temp_path, policy_path);
  ENVOY_LOG_MISC(debug,
                 "Updating Cilium Network Policy from file \'{}\'->\'{}\' instead "
                 "of using gRPC",
                 temp_path, policy_path);

  // Reduce flakiness by allowing some time for the policy to be updated before the following test
  absl::SleepFor(absl::Milliseconds(100));

  // 2nd round, on updated policy
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogRequestTo([](const ::cilium::LogEntry& entry) {
    auto source_ip = Network::Utility::parseInternetAddressAndPort(entry.source_address())
                         ->ip()
                         ->addressAsString();
    const auto& http = entry.http();
    const auto& missing = http.missing_headers();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 2 &&
           hasHeader(missing, "header42") && hasHeader(missing, "bearer-token", "[redacted]");
  }));

  // 3rd round back to the initial policy
  TestEnvironment::renameFile(backup_path, policy_path);
  ENVOY_LOG_MISC(debug,
                 "Updating Cilium Network Policy from file \'{}\'->\'{}\' instead "
                 "of using gRPC",
                 backup_path, policy_path);

  // Reduce flakiness by allowing some time for the policy to be updated before the following test
  absl::SleepFor(absl::Milliseconds(100));

  Denied({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});

  // Validate that missing headers are access logged correctly
  EXPECT_TRUE(expectAccessLogDeniedTo([](const ::cilium::LogEntry& entry) {
    auto source_ip = Network::Utility::parseInternetAddressAndPort(entry.source_address())
                         ->ip()
                         ->addressAsString();
    const auto& http = entry.http();
    return http.rejected_headers_size() == 0 && http.missing_headers_size() == 0;
  }));
}

} // namespace Envoy
