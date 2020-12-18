#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"

#include "common/common/assert.h"
#include "common/network/address_impl.h"
#include "common/network/utility.h"

#include "common/common/thread.h"
#include "common/config/decoded_resource_impl.h"
#include "common/config/filesystem_subscription_impl.h"
#include "common/config/utility.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/protobuf.h"
#include "common/thread_local/thread_local_impl.h"
#include "extensions/filters/network/http_connection_manager/config.h"
#include "extensions/transport_sockets/tls/context_config_impl.h"
#include "extensions/transport_sockets/tls/ssl_socket.h"

#include "test/integration/http_integration.h"
#include "test/integration/ssl_utility.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"

#include "cilium/accesslog.h"
#include "cilium/bpf_metadata.h"
#include "cilium/l7policy.h"
#include "cilium/network_policy.h"
#include "cilium/socket_option.h"
#include "cilium/api/bpf_metadata.pb.validate.h"
#include "cilium/api/l7policy.pb.validate.h"

namespace Envoy {

class AccessLogServer : Logger::Loggable<Logger::Id::router> {
public:
  AccessLogServer(const std::string path) : path_(path), fd2_(-1) {
    ENVOY_LOG(critical, "Creating access log server: {}", path_);
    ::unlink(path_.c_str());
    fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd_ == -1) {
      ENVOY_LOG(error, "Can't create socket: {}", strerror(errno));
      return;
    }

    ENVOY_LOG(critical, "Binding to {}", path_);
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = {}};
    strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd_, reinterpret_cast<struct sockaddr *>(&addr),
	       sizeof(addr)) == -1) {
      ENVOY_LOG(warn, "Bind to {} failed: {}", path_, strerror(errno));
      Close();
      return;
    }

    ENVOY_LOG(critical, "Listening on {}", path_);
    if (::listen(fd_, 5) == -1) {
      ENVOY_LOG(warn, "Listen on {} failed: {}", path_, strerror(errno));
      Close();
      return;
    }

    ENVOY_LOG(critical, "Starting access log server thread fd: {}", fd_);

    thread_ = Thread::threadFactoryForTest().createThread([this]() { threadRoutine(); });
  }

  ~AccessLogServer() {
    if (fd_ >= 0) {
      Close();
      ENVOY_LOG(warn, "Waiting on access log to close: {}", strerror(errno));
      thread_->join();
      thread_.reset();
    }
  }
private:
  void Close() {
    ::shutdown(fd_, SHUT_RD);
    ::shutdown(fd2_, SHUT_RD);
    errno = 0;
    ::close(fd_);
    fd_ = -1;
    ::unlink(path_.c_str());
  }

  void threadRoutine() {
    while (fd_ >= 0) {
      ENVOY_LOG(critical, "Access Log thread started on fd: {}", fd_);
      // Accept a new connection
      struct sockaddr_un addr;
      socklen_t addr_len;
      ENVOY_LOG(warn, "Access log blocking accept on fd: {}", fd_);
      fd2_ = ::accept(fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len);
      if (fd2_ < 0) {
	ENVOY_LOG(critical, "Access log accept failed: {}", strerror(errno));
      } else {
	char buf[8192];
	while (true) {
	  ENVOY_LOG(warn, "Access log blocking recv on fd: {}", fd2_);
	  ssize_t received = ::recv(fd2_, buf, sizeof(buf), 0);
	  if (received < 0) {
	    ENVOY_LOG(warn, "Access log recv failed: {}", strerror(errno));
	    break;
	  } else if (received == 0) {
	    ENVOY_LOG(warn, "Access log recv got no data!");
	    break;
	  } else {
	    std::string data(buf, received);
	    ::cilium::LogEntry entry;
	    if (!entry.ParseFromString(data)) {
	      ENVOY_LOG(warn, "Access log parse failed!");
	    } else {
	      if (entry.method().length() > 0) {
		ENVOY_LOG(warn, "Access log deprecated format detected");
		// Deprecated format detected, map to the new one
		auto http = entry.mutable_http();
		http->set_http_protocol(entry.http_protocol());
		entry.clear_http_protocol();
		http->set_scheme(entry.scheme());
		entry.clear_scheme();
		http->set_host(entry.host());
		entry.clear_host();
		http->set_path(entry.path());
		entry.clear_path();
		http->set_method(entry.method());
		entry.clear_method();
		for (const auto& dep_hdr: entry.headers()) {
		  auto hdr = http->add_headers();
		  hdr->set_key(dep_hdr.key());
		  hdr->set_value(dep_hdr.value());
		}
		entry.clear_headers();
		http->set_status(entry.status());
		entry.clear_status();
	      }
	      ENVOY_LOG(info, "Access log entry: {}", entry.DebugString());
	    }
	  }
	}
	::close(fd2_);
	fd2_ = -1;
      }
    };
  }

  const std::string path_;
  std::atomic<int> fd_;
  std::atomic<int> fd2_;
  Thread::ThreadPtr thread_;
};

std::string host_map_config;
std::shared_ptr<const Cilium::PolicyHostMap> hostmap{nullptr};

Network::Address::InstanceConstSharedPtr original_dst_address;
std::shared_ptr<const Cilium::NetworkPolicyMap> npmap{nullptr};

std::string policy_config;

const std::string BASIC_POLICY = R"EOF(version_info: "0"
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

const std::string HEADER_ACTION_POLICY = R"EOF(version_info: "0"
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
          header_matches:
          - name: 'header42'
            match_action: FAIL_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
          - name: 'header1'
            value: 'value1'
            mismatch_action: REPLACE_ON_MISMATCH
        - headers: [ { name: ':path', safe_regex_match: { google_re2: {}, regex: '.*public$' } } ]
          header_matches:
          - name: 'user-agent'
            value: 'CuRL'
            mismatch_action: DELETE_ON_MISMATCH
        - headers: [ { name: ':authority', exact_match: 'allowedHOST' } ]
          header_matches:
          - name: 'header2'
            value: 'value2'
            mismatch_action: ADD_ON_MISMATCH
          - name: 'header42'
            match_action: DELETE_ON_MATCH
            mismatch_action: CONTINUE_ON_MISMATCH
        - headers: [ { name: ':authority', safe_regex_match: { google_re2: {}, regex: '.*REGEX.*' } } ]
          header_matches:
          - name: 'header42'
            value: '42'
            mismatch_action: DELETE_ON_MISMATCH
        - headers: [ { name: ':method', exact_match: 'PUT' }, { name: ':path', exact_match: '/public/opinions' } ]
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

const std::string TCP_POLICY = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.passer"
)EOF";

namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::BpfMetadata& config, Server::Configuration::ListenerFactoryContext& context)
    : Config(config, context) {}
  ~TestConfig() {
    hostmap.reset();
    npmap.reset();
  }

  bool getMetadata(Network::ConnectionSocket &socket) override {
    // fake setting the local address. It remains the same as required by the test infra, but it will be marked as restored
    // as required by the original_dst cluster.
    socket.restoreLocalAddress(original_dst_address);

    // TLS filter chain matches this, make namespace part of this (e.g., "default")?
    socket.setDetectedTransportProtocol("cilium:default");

    // This must be the full domain name
    socket.setRequestedServerName("localhost");

    std::string pod_ip;
    uint64_t source_identity;
    uint64_t destination_identity;
    if (is_ingress_) {
      source_identity = 1;
      destination_identity = 173;
      pod_ip = original_dst_address->ip()->addressAsString();
      ENVOY_LOG_MISC(debug, "INGRESS POD_IP: {}", pod_ip);
    } else {
      source_identity = 173;
      destination_identity = hosts_->resolve(socket.localAddress()->ip());
      pod_ip = socket.localAddress()->ip()->addressAsString();
      ENVOY_LOG_MISC(debug, "EGRESS POD_IP: {}", pod_ip);
    }
    auto policy = npmap_->GetPolicyInstance(pod_ip);

    // Set metadata for policy based listener filter chain matching
    // Note: tls_inspector may overwrite this value, if it executes after us!
    std::string l7proto;
    if (policy && policy->useProxylib(is_ingress_, 80, is_ingress_ ? source_identity : destination_identity, l7proto)) {
      std::vector<absl::string_view> protocols;
      protocols.emplace_back(l7proto);
      socket.setRequestedApplicationProtocols(protocols);
      ENVOY_LOG_MISC(info, "setRequestedApplicationProtocols({})", l7proto);
    }

    socket.addOption(std::make_shared<Cilium::SocketOption>(policy, maps_, source_identity, destination_identity, is_ingress_, 80, is_ingress_ ? 10000 : 10001, std::move(pod_ip), nullptr));

    return true;
  }
};

class TestInstance : public Instance {
public:
  TestInstance(const ConfigSharedPtr& config) : Instance(config) {}
};

} // namespace BpfMetadata
} // namespace Filter

namespace Server {
namespace Configuration {

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(const std::string& config, Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
      "cilium_host_map_singleton", [&config, &context] {
	std::string path = TestEnvironment::writeStringToFileForTest("host_map.yaml", config);
	ENVOY_LOG_MISC(debug, "Loading Cilium Host Map from file \'{}\' instead of using gRPC",
		       path);

        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path, context.api());
        Envoy::Config::SubscriptionStats stats =
	  Envoy::Config::Utility::generateStats(context.scope());
        auto map = std::make_shared<Cilium::PolicyHostMap>(context.threadLocal());
	auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl>(
            context.dispatcher(), path, *map, *map, stats, ProtobufMessage::getNullValidationVisitor(), context.api());
        map->startSubscription(std::move(subscription));
        return map;
    });
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(const std::string& config, Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      "cilium_network_policy_singleton", [&config, &context] {
        // File subscription.
	std::string path = TestEnvironment::writeStringToFileForTest("network_policy.yaml", config);
	ENVOY_LOG_MISC(debug, "Loading Cilium Network Policy from file \'{}\' instead of using gRPC", path);
        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path, context.api());
        Envoy::Config::SubscriptionStats stats = Envoy::Config::Utility::generateStats(context.scope());
        auto map = std::make_shared<Cilium::NetworkPolicyMap>(context);
        auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl>(
            context.dispatcher(), path, *map, map->resource_decoder_, stats, ProtobufMessage::getNullValidationVisitor(), context.api());
	map->startSubscription(std::move(subscription));
	return map;
      });
}

} // namespace

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class TestBpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb
  createListenerFilterFactoryFromProto(const Protobuf::Message& proto_config,
				       const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
				       ListenerFactoryContext &context) override {
    // Create the file-based policy map before the filter is created, so that the singleton
    // is set before the gRPC subscription is attempted.
    hostmap = createHostMap(host_map_config, context);
    // Create the file-based policy map before the filter is created, so that the singleton
    // is set before the gRPC subscription is attempted.
    npmap = createPolicyMap(policy_config, context);

    auto config = std::make_shared<Filter::BpfMetadata::TestConfig>(
        MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config, context.messageValidationVisitor()), context);

    return [listener_filter_matcher, config](
               Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(
          listener_filter_matcher,
          std::make_unique<Filter::BpfMetadata::TestInstance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() const override { return "test_bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<TestBpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Cilium {

class TestConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Http::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config, context.messageValidationVisitor()), context);
    return [config](
               Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::L7Policy>();
  }

  std::string name() const override { return "test_l7policy"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    TestConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Cilium

// params: is_ingress ("true", "false")
const std::string cilium_proxy_config_fmt = R"EOF(
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
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
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
)EOF";

class CiliumHttpIntegrationTest
  : public HttpIntegrationTest,
    public testing::TestWithParam<Network::Address::IpVersion> {

public:
  CiliumHttpIntegrationTest(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), realTime(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
    // Undo legacy compat rename done by HttpIntegrationTest constructor.
    // config_helper_.renameListener("cilium");
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumHttpIntegrationTest() {
  }  
  /**
   * Initializer for an individual integration test.
   */
  void initialize() override {
    HttpIntegrationTest::initialize();
    // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
    if (GetParam() == Network::Address::IpVersion::v4) {
      original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    } else {
      original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    }
  }

  void Denied(Http::TestRequestHeaderMapImpl&& headers) {
    policy_config = TestEnvironment::substitute(HEADER_ACTION_POLICY, GetParam());
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    response->waitForEndStream();

    uint64_t status;
    ASSERT_TRUE(absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
    EXPECT_EQ(403, status);
  }

  void Accepted(Http::TestRequestHeaderMapImpl&& headers) {
    policy_config = TestEnvironment::substitute(HEADER_ACTION_POLICY, GetParam());
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    uint64_t status;
    ASSERT_TRUE(absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
    EXPECT_EQ(200, status);
  }

  void InvalidHostMap(const std::string& config, const char* exmsg) {
    std::string path = TestEnvironment::writeStringToFileForTest("host_map_fail.yaml", config);
    envoy::api::v2::DiscoveryResponse message;
    ThreadLocal::InstanceImpl tls;

    MessageUtil::loadFromFile(path, message, ProtobufMessage::getNullValidationVisitor(), *api_.get());
    Envoy::Cilium::PolicyHostMap hmap(tls);
    const auto decoded_resources =
      Envoy::Config::DecodedResourcesWrapper(hmap, message.resources(), message.version_info());

    EXPECT_THROW_WITH_MESSAGE(hmap.onConfigUpdate(decoded_resources.refvec_, message.version_info()), EnvoyException, exmsg);
    tls.shutdownGlobalThreading();
  }

  AccessLogServer accessLogServer_;
};

class CiliumIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumIntegrationTest()
    : CiliumHttpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_proxy_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationTest, HostMapValid) {
  std::string config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.1/32", "::1/128" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/8", "beef::/63" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "0.0.0.0/0", "::/0" ]
)EOF";

  std::string path = TestEnvironment::writeStringToFileForTest("host_map_success.yaml", config);
  envoy::api::v2::DiscoveryResponse message;
  ThreadLocal::InstanceImpl tls;

  MessageUtil::loadFromFile(path, message, ProtobufMessage::getNullValidationVisitor(), *api_.get());
  auto hmap = std::make_shared<Envoy::Cilium::PolicyHostMap>(tls);
  const auto decoded_resources =
    Envoy::Config::DecodedResourcesWrapper(*hmap, message.resources(), message.version_info());

  VERBOSE_EXPECT_NO_THROW(hmap->onConfigUpdate(decoded_resources.refvec_, message.version_info()));

  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.1").ip()), 173);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.0").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.2").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("127.0.0.1").ip()), 1);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("127.0.0.2").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("126.0.0.2").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("128.0.0.0").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("::1").ip()), 1);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("::").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("f00d::1").ip()), 173);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("f00d::").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef::1.2.3.4").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:1::").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:1::42").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:2::").ip()), 12);

  tls.shutdownGlobalThreading();
}

TEST_P(CiliumIntegrationTest, HostMapInvalidNonCIDRBits) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1/32", "127.0.0.1/31" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '127.0.0.1/31'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "::1/63" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '::1/63'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/33" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/33'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/129" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/129'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/32a" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/32a'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths3) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/ 32" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/ 32'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/128 " ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/128 '");
  }
}

TEST_P(CiliumIntegrationTest, HostMapDuplicateEntry) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "127.0.0.1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '127.0.0.1' for policy 11, already mapped to 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '::1' for policy 11, already mapped to 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapDuplicateEntry2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "127.0.0.0/8", "127.0.0.1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '127.0.0.1' for policy 12, already mapped to 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "f00f::/16", "::1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '::1' for policy 12, already mapped to 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidAddress) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "255.256.0.0" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry '255.256.0.0' for policy 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "fOOd::1" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry 'fOOd::1' for policy 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidAddress2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "255.255.0.0 " ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry '255.255.0.0 ' for policy 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "f00d:: 1" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry 'f00d:: 1' for policy 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidDefaults) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "0.0.0.0/0", "128.0.0.0/0" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '128.0.0.0/0'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::/0", "8000::/0" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '8000::/0'");
  }
}

TEST_P(CiliumIntegrationTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}, {"header1", "value1"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefixStrippedHeader) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}, {"header1", "value2"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathRegexDeleteHeader) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}, {"User-Agent", "test"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostRegexDeleteHeader) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}, {"header42", "test"}});
}

TEST_P(CiliumIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostString) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationTest, AllowedReplaced) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationTest, Denied42) {
  Denied({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}, {"header42", "anything"}});
}

TEST_P(CiliumIntegrationTest, AllowedReplacedAndDeleted) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "allowedHOST"}, {"header42", "anything"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}});
}

TEST_P(CiliumIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, DuplicatePort) {
  // This policy has a duplicate port number, and will be rejected.
  policy_config = TestEnvironment::substitute(BASIC_POLICY, GetParam()) + R"EOF(  - port: 80
    rules:
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', safe_regex_match: { google_re2: {}, regex: '/only-2-allowed' } } ]
)EOF";

  // This would normally be allowed, but since the policy fails, everything will be rejected.
  Http::TestRequestHeaderMapImpl headers =
    {{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}};
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  response->waitForEndStream();

  uint64_t status;
  ASSERT_TRUE(absl::SimpleAtoi(response->headers().Status()->value().getStringView(), &status));
  EXPECT_EQ(403, status);
}

class CiliumIntegrationEgressTest : public CiliumHttpIntegrationTest {
public:
  CiliumIntegrationEgressTest()
    : CiliumHttpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_proxy_config_fmt, GetParam()), "false")) {
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

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumIntegrationEgressTest,
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

//
// Cilium filters with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_tcp_proxy_config_fmt = R"EOF(
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
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumTcpIntegrationTest : public BaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config)
    : BaseIntegrationTest(GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
    enable_half_close_ = true;
  }

  virtual std::string testPolicy() {
    return TestEnvironment::substitute(TCP_POLICY, GetParam());
  }

  void initialize() override {
    policy_config = testPolicy();
    config_helper_.renameListener("tcp_proxy");
    BaseIntegrationTest::initialize();
    // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
    if (GetParam() == Network::Address::IpVersion::v4) {
      original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    } else {
      original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    }
  }

  void TearDown() override {
    npmap.reset();
  }

  AccessLogServer accessLogServer_;
};

class CiliumTcpProxyIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumTcpProxyIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tcp_proxy_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumTcpProxyIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

// Test upstream writing before downstream downstream does.
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamWritesFirst) {
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
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamDisconnect) {
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
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyDownstreamDisconnect) {
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
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect(true));
  tcp_client->waitForDisconnect();
}

TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyLargeWrite) {
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
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")
          ->value();
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
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
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

  test_server_->waitForCounterGe("cluster.cluster1.upstream_flow_control_paused_reading_total", 1);
  EXPECT_EQ(test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
                ->value(),
            0);
  tcp_client->readDisable(false);
  tcp_client->waitForData(data);
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_GE(upstream_pauses, upstream_resumes);
  EXPECT_GT(upstream_resumes, 0);
}

// Test that an upstream flush works correctly (all data is flushed)
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();

  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
  EXPECT_EQ(test_server_->gauge("tcp.tcp_stats.upstream_flush_active")->value(), 0);
}

// Test that Envoy doesn't crash or assert when shutting down with an upstream flush active
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamFlushEnvoyExit) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}

//
// Cilium Go test parser "linetester" with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_linetester_config_fmt = R"EOF(
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
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

const std::string TCP_POLICY_LINEPARSER = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.lineparser"
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.lineparser"
)EOF";

class CiliumGoLinetesterIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumGoLinetesterIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_linetester_config_fmt, GetParam()), "true")) {}

  std::string testPolicy() override {
    return TestEnvironment::substitute(TCP_POLICY_LINEPARSER, GetParam());
  }
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumGoLinetesterIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

static FakeRawConnection::ValidatorFunction noMatch(const char* data_to_not_match) {
  return [data_to_not_match](const std::string& data) -> bool {
    auto found = data.find(data_to_not_match);
    return found == std::string::npos;
  };
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("PASS reply direction\n"));
  tcp_client->waitForData("PASS reply direction\n");

  ASSERT_TRUE(tcp_client->write("PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserPartialLines) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply "));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  ASSERT_TRUE(fake_upstream_connection->write("direction\nPASS"));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  ASSERT_TRUE(fake_upstream_connection->write(" reply direction\n"));
  tcp_client->waitForData("PASS reply direction\n");

  ASSERT_TRUE(tcp_client->write("PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInject) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(tcp_client->write("INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("PASS reply direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("PASS reply direction\n", false);
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInjectPartial) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("PASS reply"));
  ASSERT_TRUE(tcp_client->write("INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("PASS original direction\n"));

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("PASS reply direction\n", false);
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInjectPartialMultiple) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("PASS reply"));
  ASSERT_TRUE(tcp_client->write("INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("DROP original direction\n"));
  ASSERT_TRUE(tcp_client->write("INSERT original direction\n"));

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("PASS reply direction\n", false);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("INSERT original direction\n")));
  ASSERT_TRUE(fake_upstream_connection->waitForData(noMatch("DROP")));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("PASS2 reply direction\n"));
  tcp_client->waitForData("PASS2 reply direction\n", false);
  
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

//
// Cilium Go test parser "blocktester" with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_blocktester_config_fmt = R"EOF(
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
      name: test_bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
          proxylib_params:
            access-log-path: "{{ test_udsdir }}/access_log.sock"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

const std::string TCP_POLICY_BLOCKPARSER = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.blockparser"
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      l7_proto: "test.blockparser"
)EOF";

class CiliumGoBlocktesterIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumGoBlocktesterIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_blocktester_config_fmt, GetParam()), "true")) {}

  std::string testPolicy() override {
    return TestEnvironment::substitute(TCP_POLICY_BLOCKPARSER, GetParam());
  }
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumGoBlocktesterIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply direction\n"));
  tcp_client->waitForData("24:PASS reply direction\n");

  ASSERT_TRUE(tcp_client->write("27:PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserPartialBlocks) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply "));
  ASSERT_TRUE(fake_upstream_connection->write("direction\n24:PASS"));
  ASSERT_TRUE(fake_upstream_connection->write(" reply direction\n"));
  tcp_client->waitForData("24:PASS reply direction\n");

  ASSERT_TRUE(tcp_client->write("27:PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInject) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(tcp_client->write("26:INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("27:PASS original direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply direction\n"));

  // These can in principle arrive in either order
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("24:PASS reply direction\n", false);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInjectPartial) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply"));
  ASSERT_TRUE(tcp_client->write("26:INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("27:PASS original direction\n"));

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("24:PASS reply direction\n", false);
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInjectPartialMultiple) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply"));
  ASSERT_TRUE(tcp_client->write("26:INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("27:DROP original direction\n"));
  ASSERT_TRUE(tcp_client->write("29:INSERT original direction\n"));

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  ASSERT_TRUE(fake_upstream_connection->write(" dire"));

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  ASSERT_TRUE(fake_upstream_connection->write("ction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("24:PASS reply direction\n", false);
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("29:INSERT original direction\n")));
  ASSERT_TRUE(fake_upstream_connection->waitForData(noMatch("DROP")));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("25:PASS2 reply direction\n"));
  tcp_client->waitForData("25:PASS2 reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInjectBufferOverflow) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(tcp_client->write("26:INJECT reply direction\n"));
  ASSERT_TRUE(tcp_client->write("27:DROP original direction\n"));

  char buf[5000];
  memset(buf, 'A', sizeof buf);
  strncpy(buf, "5000:INSERT original direction", 30);
  buf[sizeof buf - 1] = '\n';
  
  ASSERT_TRUE(tcp_client->write(buf));
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch(buf)));
  ASSERT_TRUE(fake_upstream_connection->waitForData(noMatch("DROP")));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("25:PASS2 reply direction\n"));
  tcp_client->waitForData("25:PASS2 reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

namespace Cilium {

extern const absl::string_view pathSV;
extern const absl::string_view methodSV;
extern const absl::string_view authoritySV;
extern const absl::string_view xForwardedProtoSV;

class CiliumTest : public testing::Test {
protected:
  Event::SimulatedTimeSystem time_system_;
  Network::Address::InstanceConstSharedPtr local_address_;
  Network::Address::InstanceConstSharedPtr remote_address_;  
};

TEST_F(CiliumTest, AccessLog) {
  Http::TestRequestHeaderMapImpl headers{
    {":method", "GET"},
      {":path", "/"},
	{":authority", "host"},
	  {"x-forwarded-proto", "http"},
	    {"x-request-id", "ba41267c-cfc2-4a92-ad3e-cd084ab099b4"}};
  NiceMock<StreamInfo::MockStreamInfo> stream_info;
  stream_info.protocol_ = Http::Protocol::Http11;
  stream_info.start_time_ = time_system_.systemTime();
  Network::MockConnection connection;
  Network::Socket::OptionsSharedPtr options = std::make_shared<Network::Socket::Options>();
  options->push_back(std::make_shared<Cilium::SocketOption>(nullptr, nullptr, 1, 173, true, 80, 10000, "1.2.3.4", nullptr));
  local_address_ = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 80);
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("5.6.7.8", 45678);

  ENVOY_LOG_MISC(error, "source_address: {}", remote_address_->asString());
  ENVOY_LOG_MISC(error, "destination_address: {}", local_address_->asString());

  EXPECT_CALL(connection, socketOptions()).WillOnce(testing::ReturnRef(options));
  EXPECT_CALL(connection, localAddress()).WillRepeatedly(testing::ReturnRef(local_address_));
  EXPECT_CALL(connection, remoteAddress()).WillRepeatedly(testing::ReturnRef(remote_address_));

  AccessLog::Entry log;

  log.InitFromRequest("1.2.3.4", true, &connection, headers, stream_info);

  EXPECT_EQ(log.entry_.is_ingress(), true);
  EXPECT_EQ(log.entry_.entry_type(), ::cilium::EntryType::Request);
  EXPECT_NE(log.entry_.timestamp(), 0);
  EXPECT_STREQ(log.entry_.policy_name().c_str(), "1.2.3.4");
  EXPECT_STREQ("1.2.3.4:80", log.entry_.destination_address().c_str());
  EXPECT_STREQ("5.6.7.8:45678", log.entry_.source_address().c_str());
  EXPECT_EQ(1, log.entry_.source_security_id());
  EXPECT_EQ(173, log.entry_.destination_security_id());

  EXPECT_EQ(log.entry_.has_http(), true);
  EXPECT_EQ(::cilium::HttpProtocol::HTTP11, log.entry_.http().http_protocol());
  EXPECT_STREQ("/", log.entry_.http().path().c_str());
  EXPECT_STREQ("GET", log.entry_.http().method().c_str());
  EXPECT_STREQ("host", log.entry_.http().host().c_str());
  EXPECT_STREQ("http", log.entry_.http().scheme().c_str());

  EXPECT_EQ(log.entry_.http().headers_size(), 1);
  EXPECT_STREQ(log.entry_.http().headers(0).key().c_str(), "x-request-id");
  EXPECT_STREQ(log.entry_.http().headers(0).value().c_str(), "ba41267c-cfc2-4a92-ad3e-cd084ab099b4");
}

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
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
          stat_prefix: tcp_stats
          cluster: tls-cluster
)EOF";

const std::string cilium_listener_tls_context_fmt = R"EOF(
      transport_socket:
        name: "cilium.tls_wrapper"
)EOF";

Network::TransportSocketFactoryPtr
createClientSslTransportSocketFactory(Ssl::ContextManager& context_manager, Api::Api& api) {
  std::string yaml_plain = R"EOF(
  common_tls_context:
    validation_context:
      trusted_ca:
        filename: "{{ test_rundir }}/test/config/integration/certs/cacert.pem"
)EOF";

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext tls_context;
  TestUtility::loadFromYaml(TestEnvironment::substitute(yaml_plain), tls_context);

  NiceMock<Server::Configuration::MockTransportSocketFactoryContext> mock_factory_ctx;
  ON_CALL(mock_factory_ctx, api()).WillByDefault(testing::ReturnRef(api));
  auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ClientContextConfigImpl>(
      tls_context, mock_factory_ctx);
  static auto* client_stats_store = new Stats::TestIsolatedStoreImpl();
  return Network::TransportSocketFactoryPtr{
      new Extensions::TransportSockets::Tls::ClientSslSocketFactory(std::move(cfg), context_manager,
                                                                    *client_stats_store)};
}

class CiliumTLSIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumTLSIntegrationTest(const std::string& config)
    : CiliumTcpIntegrationTest(config) {
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }

  void initialize() override {
    CiliumTcpIntegrationTest::initialize();

    payload_reader_.reset(new WaitForPayloadReader(*dispatcher_));
  }

  void createUpstreams() override {
    if (upstream_tls_) {
      fake_upstreams_.emplace_back(new FakeUpstream(
          createUpstreamSslContext(), 0, FakeHttpConnection::Type::HTTP1, version_, timeSystem(),
          true));
    } else {
      CiliumTcpIntegrationTest::createUpstreams(); // maybe BaseIntegrationTest::createUpstreams()
    }
  }

  void TearDown() override {
    CiliumTcpIntegrationTest::TearDown();
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

    auto cfg = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
        tls_context, factory_context_);

    static Stats::Scope* upstream_stats_store = new Stats::IsolatedStoreImpl();
    return std::make_unique<Extensions::TransportSockets::Tls::ServerSslSocketFactory>(
        std::move(cfg), context_manager_, *upstream_stats_store, std::vector<std::string>{});
  }

  void setupConnections() {
    initialize();
    fake_upstreams_[0]->setReadDisableOnNewConnection(false);

    // Set up the mock buffer factory so the newly created SSL client will have a mock write
    // buffer. This allows us to track the bytes actually written to the socket.

    EXPECT_CALL(*mock_buffer_factory_, create_(_, _, _))
        .Times(1)
        .WillOnce(Invoke([&](std::function<void()> below_low,
                             std::function<void()> above_high,
                             std::function<void()> above_overflow) -> Buffer::Instance* {
          client_write_buffer_ = new NiceMock<MockWatermarkBuffer>(below_low, above_high, above_overflow);
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
    ssl_client_ =
        dispatcher_->createClientConnection(address, Network::Address::InstanceConstSharedPtr(),
                                            context_->createTransportSocket(nullptr), nullptr);

    // Perform the SSL handshake. Loopback is whitelisted in tcp_proxy.json for the ssl_auth
    // filter so there will be no pause waiting on auth data.
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
    while (client_write_buffer_->bytes_drained() != data_to_send_upstream.size()) {
      dispatcher_->run(Event::Dispatcher::RunType::NonBlock);
    }

    // Make sure the data makes it upstream.
    ASSERT_TRUE(fake_upstream_connection->waitForData(data_to_send_upstream.size()));

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

const std::string TCP_POLICY_UPSTREAM_TLS = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '{{ ntop_ip_loopback_address }}'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      upstream_tls_context:
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUQygBeIE4nv9JGaDKixnhwkK5viEwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMTkwNzA4MjE0\nNTU2WhcNMjEwNzA3MjE0NTU2WjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMJ7AetbhOCUxB/A\nyYt+4rxyMVUFX9izqbOU9nuUxsB/avGhYpVjj5cNaLPdGX+c7g65Vz0yGDSskDGD\nukcSFqRSZ2E4/S4gKSIMEslBr2OX+Dqh0XmoAwl4IrtZefCE3inivJdzm0JwI7Yr\nk2qQqsTpJnsWkMSxXUQJYTJ56UFXTkKqF3jSReIQtFMV65T/2x2NLRJ8KuMS7Mbo\nBTBATRsUfbJJWCnzcp2LrKV5sZ/HsJLK/F74jdcvfJQMW49Lq1TZaB5NYSVyFEf6\ntiT43JOcvVkRPBgHDtaiDhWF2WTmPSEB6cHaRwGgBFwjQ1SvZR6f6xexocn44GZE\noSqWJN8CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFOLTMLryzNAcuxe3cKEhClkL7IduMB8GA1UdIwQYMBaAFOLTMLry\nzNAcuxe3cKEhClkL7IduMA0GCSqGSIb3DQEBCwUAA4IBAQBT88sT8RsoAk6PnnVs\nKWBoC75BnIZr8o1nxBK0zog6Ez4J32aVzEXPicgBg6hf6v77eqbbQ+O7Ayf+YQWj\nl9w9IiXRW1x94tKBrX44O85qTr/xtkfpmQWGKq5fBpdJnZp7lSfGfaG9gasPUNpG\ngfvF/vlYrrJoyvUOG6HQjZ7n7m6f8GEUymCtC68oJcLVL0xkvx/jcvGeJfI5U6yr\nz9nc1W7FcOhrFEetOIH2BwlIN5To3vPbN4zEzt9VPUHZ3m2899hUiMZJaanEexp7\nTZJJ12rHSIJ4MKwQQ5fEmioeluM0uY7EIR72VEsudA8bkXSkbDGs6Q49K9OX+nRB\n4P3c\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEYTCCA0mgAwIBAgIJAILStmLgUUcVMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\nc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2luZWVyaW5nMRAw\nDgYDVQQDDAdUZXN0IENBMB4XDTE4MTIxNzIwMTgwMFoXDTIwMTIxNjIwMTgwMFow\ngaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T\nYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2lu\nZWVyaW5nMRowGAYDVQQDDBFUZXN0IEJhY2tlbmQgVGVhbTEkMCIGCSqGSIb3DQEJ\nARYVYmFja2VuZC10ZWFtQGx5ZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321IUTLs\n4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPqUoc9\ntzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzcynL/\niflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6FopYR\nV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v3sYl\n3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABo4HAMIG9MAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATBB\nBgNVHREEOjA4hh5zcGlmZmU6Ly9seWZ0LmNvbS9iYWNrZW5kLXRlYW2CCGx5ZnQu\nY29tggx3d3cubHlmdC5jb20wHQYDVR0OBBYEFLHmMm0DV9jCHJSWVRwyPYpBw62r\nMB8GA1UdIwQYMBaAFBQz1vaSbPuePL++7GTMqLAMtk3kMA0GCSqGSIb3DQEBCwUA\nA4IBAQAwx3/M2o00W8GlQ3OT4y/hQGb5K2aytxx8QeSmJaaZTJbvaHhe0x3/fLgq\nuWrW3WEWFtwasilySjOrFOtB9UNmJmNOHSJD3Bslbv5htRaWnoFPCXdwZtVMdoTq\nIHIQqLoos/xj3kVD5sJSYySrveMeKaeUILTkb5ZubSivye1X2yiJLR7AtuwuiMio\nCdIOqhn6xJqYhT7z0IhdKpLNPk4w1tBZSKOXqzrXS4uoJgTC67hWslWWZ2VC6IvZ\nFmKuuGZamCCj6F1QF2IjMVM8evl84hEnN0ajdkA/QWnil9kcWvBm15Ho+oTvvJ7s\nM8MD3RDSq/90FSiME4vbyNEyTmj0\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321I\nUTLs4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPq\nUoc9tzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzc\nynL/iflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6F\nopYRV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v\n3sYl3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABAoIBAQCkPLR1sy47BokN\nc/BApn9sn5/LZH7ujBTjDce6hqzLIVZn6/OKEfj1cbWiSd6KxRv8/B/vMykpbZ5/\n/w9eZP4imEGmChWhwruh8zHOrdAYhEXmuwZxtgnLurQ2AHTcX9hPCYB0Va76H3ZI\nQ65JUm6NaeQOlGT6ExjrIA2rTYJFM84I1xH3XbDulS9S2FXNP9RIjV70HzvZw2LR\n1qSNfrnGAEbUCdrZT4BAYTGam5L061ofencYLAorr8K0eVWhUjGV9Jjpq8aG8zy5\nOy1070I0d7Iexfu7T1sQDIqpNkOtQxI8feQEKeKlRKYx6YEQ9vaVwBGa0SBVxQem\nE3YdXBnBAoGBAORlz8wlYqCx25htO/eLgr9hN+eKNhNTo4l905aZrG8SPinaHl15\nn+dQdzlJMVm/rh5+VE0NR0U/vzd3SrdnzczksuGFn0Us/Yg+zOl1+8+GFAtqw3js\nudFLKksChz4Rk/fZo2djtSiFS5aGBtw0Z9T7eorubkTSSfJ7IT99HIu5AoGBANGL\n0ff5U2LV/Y/opKP7xOlxSCVI617N5i0sYMJ9EUaWzvquidzM46T4fwlAeIvAtks7\nACO1cRPuWredZ/gEZ3RguZMxs6llwxwVCaQk/2vbOfATWmyqpGC9UBS/TpYVXbL5\nWUMsdBs4DdAFz8aCrrFBcDeCg4V4w+gHYkFV+LetAoGAB3Ny1fwaPZfPzCc0H51D\nhK7NPhZ6MSM3YJLkRjN5Np5nvMHK383J86fiW9IRdBYWvhPs+B6Ixq+Ps2WG4HjY\nc+i6FTVgvsb69mjmEm+w6VI8cSroeZdvcG59ULkiZFn6c8l71TGhhVLj5mM08hYb\nlQ0nMEUa/8/Ebc6qhQG13rECgYEAm8AZaP9hA22a8oQxG9HfIsSYo1331JemJp19\nrhHX7WfaoGlq/zsrWUt64R2SfA3ZcUGBcQlD61SXCTNuO+LKIq5iQQ4IRDjnNNBO\nQjtdvoVMIy2/YFXVqDIOe91WRCfNZWIA/vTjt/eKDLzFGv+3aPkCt7/CkkqZErWq\nSnXkUGECgYAvkemYu01V1WcJotvLKkVG68jwjMq7jURpbn8oQVlFR8zEh+2UipLB\nOmrNZjmdrhQe+4rzs9XCLE/EZsn7SsygwMyVhgCYzWc/SswADq7Wdbigpmrs+grW\nfg7yxbPGinTyraMd0x3Ty924LLscoJMWUBl7qGeQ2iUdnELmZgLN2Q==\n-----END RSA PRIVATE KEY-----\n"
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
)EOF";

class CiliumTLSProxyIntegrationTest : public CiliumTLSIntegrationTest {
public:
  CiliumTLSProxyIntegrationTest() : CiliumTLSIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tls_tcp_proxy_config_fmt, GetParam()), "true")) {}

  std::string testPolicy() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS, GetParam());
  }
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumTLSProxyIntegrationTest,
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
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect(true));
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
#ifndef __aarch64__
// Test that a downstream flush works correctly (all data is flushed)
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
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

  test_server_->waitForCounterGe("cluster.tls-cluster.upstream_flow_control_paused_reading_total", 1);
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
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able to wait for
  // ConnectionEvent::Connected, which is raised after the TLS handshake has completed,
  // but just wait for a while instead for now.
  usleep(10000);

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  tcp_client->waitForHalfClose();

  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
  EXPECT_EQ(test_server_->gauge("tcp.tcp_stats.upstream_flush_active")->value(), 0);
}

// Test that Envoy doesn't crash or assert when shutting down with an upstream flush active
TEST_P(CiliumTLSProxyIntegrationTest, CiliumTLSProxyUpstreamFlushEnvoyExit) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));

  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  // Disabling read does not let the TLS handshake to finish. We should be able to wait for
  // ConnectionEvent::Connected, which is raised after the TLS handshake has completed,
  // but just wait for a while instead for now.
  usleep(10000);

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  ASSERT_TRUE(tcp_client->write(data, true));

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}
#endif
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
    - name: "envoy.listener.tls_inspector"
    filter_chains:
    - filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
          proxylib: "proxylib/libcilium.so"
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
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
          "@type": type.googleapis.com/envoy.config.filter.network.tcp_proxy.v2.TcpProxy
          stat_prefix: tcp_stats
          cluster: tls-cluster
)EOF";

class CiliumDownstreamTLSIntegrationTest : public CiliumTLSIntegrationTest {
public:
  CiliumDownstreamTLSIntegrationTest() : CiliumTLSIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tls_downstream_tcp_proxy_config_fmt, GetParam()), "true")) {}

  std::string testPolicy() override {
    return TestEnvironment::substitute(TCP_POLICY_UPSTREAM_TLS, GetParam());
  }
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumDownstreamTLSIntegrationTest,
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
  AssertionResult result = fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection);
  RELEASE_ASSERT(result, result.message());

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ssl_client_->dispatcher().run(Event::Dispatcher::RunType::Block);
  EXPECT_TRUE(payload_reader_->readLastByte());
  EXPECT_FALSE(connect_callbacks_.closed());

  const std::string& val("data");
  Buffer::OwnedImpl buffer(val);
  ssl_client_->write(buffer, false);
  while (client_write_buffer_->bytes_drained() != val.size()) {
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
)EOF";

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
        trusted_ca: "-----BEGIN CERTIFICATE-----\nMIID7zCCAtegAwIBAgIUQygBeIE4nv9JGaDKixnhwkK5viEwDQYJKoZIhvcNAQEL\nBQAwfzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBEx5ZnQxGTAXBgNVBAsMEEx5ZnQgRW5n\naW5lZXJpbmcxGTAXBgNVBAMMEFRlc3QgVXBzdHJlYW0gQ0EwHhcNMTkwNzA4MjE0\nNTU2WhcNMjEwNzA3MjE0NTU2WjB/MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwETHlmdDEZ\nMBcGA1UECwwQTHlmdCBFbmdpbmVlcmluZzEZMBcGA1UEAwwQVGVzdCBVcHN0cmVh\nbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMJ7AetbhOCUxB/A\nyYt+4rxyMVUFX9izqbOU9nuUxsB/avGhYpVjj5cNaLPdGX+c7g65Vz0yGDSskDGD\nukcSFqRSZ2E4/S4gKSIMEslBr2OX+Dqh0XmoAwl4IrtZefCE3inivJdzm0JwI7Yr\nk2qQqsTpJnsWkMSxXUQJYTJ56UFXTkKqF3jSReIQtFMV65T/2x2NLRJ8KuMS7Mbo\nBTBATRsUfbJJWCnzcp2LrKV5sZ/HsJLK/F74jdcvfJQMW49Lq1TZaB5NYSVyFEf6\ntiT43JOcvVkRPBgHDtaiDhWF2WTmPSEB6cHaRwGgBFwjQ1SvZR6f6xexocn44GZE\noSqWJN8CAwEAAaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw\nHQYDVR0OBBYEFOLTMLryzNAcuxe3cKEhClkL7IduMB8GA1UdIwQYMBaAFOLTMLry\nzNAcuxe3cKEhClkL7IduMA0GCSqGSIb3DQEBCwUAA4IBAQBT88sT8RsoAk6PnnVs\nKWBoC75BnIZr8o1nxBK0zog6Ez4J32aVzEXPicgBg6hf6v77eqbbQ+O7Ayf+YQWj\nl9w9IiXRW1x94tKBrX44O85qTr/xtkfpmQWGKq5fBpdJnZp7lSfGfaG9gasPUNpG\ngfvF/vlYrrJoyvUOG6HQjZ7n7m6f8GEUymCtC68oJcLVL0xkvx/jcvGeJfI5U6yr\nz9nc1W7FcOhrFEetOIH2BwlIN5To3vPbN4zEzt9VPUHZ3m2899hUiMZJaanEexp7\nTZJJ12rHSIJ4MKwQQ5fEmioeluM0uY7EIR72VEsudA8bkXSkbDGs6Q49K9OX+nRB\n4P3c\n-----END CERTIFICATE-----\n"
      downstream_tls_context:
        certificate_chain: "-----BEGIN CERTIFICATE-----\nMIIEYTCCA0mgAwIBAgIJAILStmLgUUcVMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNp\nc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2luZWVyaW5nMRAw\nDgYDVQQDDAdUZXN0IENBMB4XDTE4MTIxNzIwMTgwMFoXDTIwMTIxNjIwMTgwMFow\ngaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1T\nYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARMeWZ0MRkwFwYDVQQLDBBMeWZ0IEVuZ2lu\nZWVyaW5nMRowGAYDVQQDDBFUZXN0IEJhY2tlbmQgVGVhbTEkMCIGCSqGSIb3DQEJ\nARYVYmFja2VuZC10ZWFtQGx5ZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321IUTLs\n4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPqUoc9\ntzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzcynL/\niflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6FopYR\nV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v3sYl\n3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABo4HAMIG9MAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgXgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATBB\nBgNVHREEOjA4hh5zcGlmZmU6Ly9seWZ0LmNvbS9iYWNrZW5kLXRlYW2CCGx5ZnQu\nY29tggx3d3cubHlmdC5jb20wHQYDVR0OBBYEFLHmMm0DV9jCHJSWVRwyPYpBw62r\nMB8GA1UdIwQYMBaAFBQz1vaSbPuePL++7GTMqLAMtk3kMA0GCSqGSIb3DQEBCwUA\nA4IBAQAwx3/M2o00W8GlQ3OT4y/hQGb5K2aytxx8QeSmJaaZTJbvaHhe0x3/fLgq\nuWrW3WEWFtwasilySjOrFOtB9UNmJmNOHSJD3Bslbv5htRaWnoFPCXdwZtVMdoTq\nIHIQqLoos/xj3kVD5sJSYySrveMeKaeUILTkb5ZubSivye1X2yiJLR7AtuwuiMio\nCdIOqhn6xJqYhT7z0IhdKpLNPk4w1tBZSKOXqzrXS4uoJgTC67hWslWWZ2VC6IvZ\nFmKuuGZamCCj6F1QF2IjMVM8evl84hEnN0ajdkA/QWnil9kcWvBm15Ho+oTvvJ7s\nM8MD3RDSq/90FSiME4vbyNEyTmj0\n-----END CERTIFICATE-----\n"
        private_key: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAuvPdQdmwZongPAgQho/Vipd3PZWrQ6BKxIb4l/RvqtVP321I\nUTLs4vVwpXoYJ+12L+XOO3jCInszs53tHjFpTI1GE8/sasmgR6LRr2krwSoVRHPq\nUoc9tzkDG1SzKP2TRTi1MTI3FO+TnLFahntO9Zstxhv1Epz5GZ/xQLE0/LLoRYzc\nynL/iflk18iL1KM8i0Hy4cKjclOaUdnh2nh753iJfxCSb5wJfx4FH1qverYHHT6F\nopYRV40Cg0yYXcYo8yNwrg+EBY8QAT2JOMDokXNKbZpmVKiBlh0QYMX6BBiW249v\n3sYl3Ve+fZvCkle3W0xP0xJw8PdX0NRbvGOrBQIDAQABAoIBAQCkPLR1sy47BokN\nc/BApn9sn5/LZH7ujBTjDce6hqzLIVZn6/OKEfj1cbWiSd6KxRv8/B/vMykpbZ5/\n/w9eZP4imEGmChWhwruh8zHOrdAYhEXmuwZxtgnLurQ2AHTcX9hPCYB0Va76H3ZI\nQ65JUm6NaeQOlGT6ExjrIA2rTYJFM84I1xH3XbDulS9S2FXNP9RIjV70HzvZw2LR\n1qSNfrnGAEbUCdrZT4BAYTGam5L061ofencYLAorr8K0eVWhUjGV9Jjpq8aG8zy5\nOy1070I0d7Iexfu7T1sQDIqpNkOtQxI8feQEKeKlRKYx6YEQ9vaVwBGa0SBVxQem\nE3YdXBnBAoGBAORlz8wlYqCx25htO/eLgr9hN+eKNhNTo4l905aZrG8SPinaHl15\nn+dQdzlJMVm/rh5+VE0NR0U/vzd3SrdnzczksuGFn0Us/Yg+zOl1+8+GFAtqw3js\nudFLKksChz4Rk/fZo2djtSiFS5aGBtw0Z9T7eorubkTSSfJ7IT99HIu5AoGBANGL\n0ff5U2LV/Y/opKP7xOlxSCVI617N5i0sYMJ9EUaWzvquidzM46T4fwlAeIvAtks7\nACO1cRPuWredZ/gEZ3RguZMxs6llwxwVCaQk/2vbOfATWmyqpGC9UBS/TpYVXbL5\nWUMsdBs4DdAFz8aCrrFBcDeCg4V4w+gHYkFV+LetAoGAB3Ny1fwaPZfPzCc0H51D\nhK7NPhZ6MSM3YJLkRjN5Np5nvMHK383J86fiW9IRdBYWvhPs+B6Ixq+Ps2WG4HjY\nc+i6FTVgvsb69mjmEm+w6VI8cSroeZdvcG59ULkiZFn6c8l71TGhhVLj5mM08hYb\nlQ0nMEUa/8/Ebc6qhQG13rECgYEAm8AZaP9hA22a8oQxG9HfIsSYo1331JemJp19\nrhHX7WfaoGlq/zsrWUt64R2SfA3ZcUGBcQlD61SXCTNuO+LKIq5iQQ4IRDjnNNBO\nQjtdvoVMIy2/YFXVqDIOe91WRCfNZWIA/vTjt/eKDLzFGv+3aPkCt7/CkkqZErWq\nSnXkUGECgYAvkemYu01V1WcJotvLKkVG68jwjMq7jURpbn8oQVlFR8zEh+2UipLB\nOmrNZjmdrhQe+4rzs9XCLE/EZsn7SsygwMyVhgCYzWc/SswADq7Wdbigpmrs+grW\nfg7yxbPGinTyraMd0x3Ty924LLscoJMWUBl7qGeQ2iUdnELmZgLN2Q==\n-----END RSA PRIVATE KEY-----\n"
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
    fake_upstreams_[0]->set_allow_unexpected_disconnects(allow_unexpected_disconnects_);

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
    allow_unexpected_disconnects_ = true;
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
  bool allow_unexpected_disconnects_{false};

  // Downstream
  Network::TransportSocketFactoryPtr context_;
};

class CiliumTLSHttpIntegrationTest : public CiliumHttpTLSIntegrationTest {
public:
  CiliumTLSHttpIntegrationTest()
    : CiliumHttpTLSIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tls_http_proxy_config_fmt + cilium_listener_tls_context_fmt, GetParam()), "true")) {}
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
