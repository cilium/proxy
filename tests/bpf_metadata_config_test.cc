#include "gmock/gmock.h"
#include <gmock/gmock-actions.h>
#include <gmock/gmock-spec-builders.h>
#include <gtest/gtest.h>
#include <spdlog/common.h>

#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "envoy/api/api.h"
#include "envoy/common/exception.h"
#include "envoy/filesystem/watcher.h"
#include "envoy/init/target.h"
#include "envoy/init/watcher.h"
#include "envoy/network/address.h"
#include "envoy/network/socket.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/common/statusor.h"
#include "source/common/config/decoded_resource_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"
#include "source/common/stats/isolated_store_impl.h"

#include "test/mocks/config/mocks.h"
#include "test/mocks/filesystem/mocks.h"
#include "test/mocks/network/connection.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/listener_factory_context.h"
#include "test/mocks/server/server_factory_context.h"
#include "test/test_common/utility.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/api/npds.pb.h"
#include "cilium/bpf_metadata.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "cilium/policy_host_map.h"
#include "cilium/policy_id.h"
#include "tests/bpf_metadata.h"
#include "tests/cilium_test_peer.h"

using testing::Mock;
using testing::NiceMock;
using testing::ReturnRef;

namespace Envoy {
namespace Cilium {
namespace {

// Test Cilium::BpfMetadata::Config filter config
// (NOT Cilium::BpfMetadata::TestConfig)

class MetadataConfigTest : public testing::Test {
protected:
  MetadataConfigTest() : api_(Api::createApiForTest()) {
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }

    ON_CALL(context_.server_factory_context_, api()).WillByDefault(testing::ReturnRef(*api_));

    ON_CALL(context_.server_factory_context_.dispatcher_, createFilesystemWatcher_())
        .WillByDefault(Invoke([]() -> Filesystem::Watcher* {
          auto watcher = new Filesystem::MockWatcher();
          EXPECT_CALL(*watcher, addWatch(_, Filesystem::Watcher::Events::MovedTo, _))
              .WillOnce(Invoke([](absl::string_view, std::uint32_t,
                                  Filesystem::Watcher::OnChangedCb) { return absl::OkStatus(); }));
          Mock::AllowLeak(watcher);
          return watcher;
        }));
    ON_CALL(context_.init_manager_, add(_))
        .WillByDefault(Invoke([this](const Init::Target& target) {
          target_handles_.push_back(target.createHandle("test"));
        }));
    ON_CALL(context_.init_manager_, initialize(_))
        .WillByDefault(Invoke([this](const Init::Watcher& watcher) {
          for (auto& handle : target_handles_) {
            handle->initialize(watcher);
          }
        }));

    options_ = std::make_shared<std::vector<Network::Socket::OptionConstSharedPtr>>();
    ON_CALL(socket_, options()).WillByDefault(ReturnRef(options_));
    ON_CALL(socket_, addOption_(_))
        .WillByDefault(Invoke([this](const Network::Socket::OptionConstSharedPtr& option) {
          options_->emplace_back(std::move(option));
        }));
    ON_CALL(socket_, addOptions_(_))
        .WillByDefault(Invoke([this](const Network::Socket::OptionsSharedPtr& options) {
          Network::Socket::appendOptions(options_, options);
        }));
    ON_CALL(socket_, ioHandle()).WillByDefault(ReturnRef(io_handle_));
    ON_CALL(testing::Const(socket_), ioHandle()).WillByDefault(ReturnRef(io_handle_));

    // Set up the original destination address.
    // - for egress this the destination pod address
    // - for ingress this is the pod IP
    // - port is a "well-known" "service" port
    original_dst_address = std::make_shared<Network::Address::Ipv4Instance>("10.2.2.2", 80);
    EXPECT_TRUE(original_dst_address);
    EXPECT_NE(nullptr, original_dst_address->ip());
    const auto original_dst_address_status =
        StatusOr<Network::Address::InstanceConstSharedPtr>(original_dst_address);
    // Set up the default local address.
    // This is the "tproxy" address the listener is listening on:
    // - IP is localhost
    // - port is allocated from the ephemeral range
    local_address_ = std::make_shared<Network::Address::Ipv4Instance>("127.0.0.1", 23456);
    EXPECT_TRUE(local_address_);
    EXPECT_NE(nullptr, local_address_->ip());

    // Set up the remote address.
    // - for egress this the pod IP
    // - for ingress this is the original source address
    // - port is from the ephemeral range
    remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("10.1.1.1", 41234);
    EXPECT_TRUE(remote_address_);
    EXPECT_NE(nullptr, remote_address_->ip());

    ON_CALL(io_handle_, localAddress()).WillByDefault(testing::Return(original_dst_address_status));
    EXPECT_EQ(&io_handle_, &socket_.ioHandle());
    const auto addr = THROW_OR_RETURN_VALUE(socket_.ioHandle().localAddress(),
                                            Network::Address::InstanceConstSharedPtr)
                          .get();
    EXPECT_NE(nullptr, addr);
  }
  ~MetadataConfigTest() override {
    hostmap.reset();
    npmap.reset();
  }

  void SetUp() override {
    // Set up default host map
    host_map_config = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 111
  host_addresses: [ "10.1.1.1", "f00d::1:1:1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 222
  host_addresses: [ "10.2.2.2", "f00d::2:2:2" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::1/128" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 8
  host_addresses: [ "10.1.1.42", "face::42" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12345678
  host_addresses: [ "192.168.1.0/24" ]
)EOF";

    // Set up default policy
    policy_config = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '10.1.1.1'
  - 'face::1:1:1'
  endpoint_id: 2048
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 222 ]
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '10.2.2.2'
  - 'face::2:2:2'
  endpoint_id: 4096
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 111 ]
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '10.1.1.42'
  - 'face::42'
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - remote_policies: [ 9999, 12345678 ]
  egress_per_port_policies:
  - port: 0
    rules:
    - remote_policies: [ 222, 9999, 12345678 ]
)EOF";
  }

  void initialize(const ::cilium::BpfMetadata& config, std::string extra_host_map_config = "",
                  std::string extra_policy_config = "") {
    socket_.connection_info_provider_ =
        std::make_shared<Network::ConnectionInfoSetterImpl>(local_address_, remote_address_);

    host_map_config += extra_host_map_config;
    policy_config += extra_policy_config;

    Cilium::TestHelper::initTestMaps(context_);

    Init::WatcherImpl watcher("metadata test", []() {});
    context_.initManager().initialize(watcher);

    config_ = std::make_shared<Cilium::BpfMetadata::Config>(config, context_);
    config_->hosts_ = hostmap;
    config_->npmap_ = npmap;
  }

  void TearDown() override {}

  Api::ApiPtr api_;
  Stats::IsolatedStoreImpl stats_;
  NiceMock<Server::Configuration::MockTransportSocketFactoryContext>
      transport_socket_factory_context_;
  NiceMock<Server::Configuration::MockListenerFactoryContext> context_;
  std::shared_ptr<Cilium::BpfMetadata::Config> config_;
  Network::Address::InstanceConstSharedPtr local_address_;
  Network::Address::InstanceConstSharedPtr remote_address_;
  NiceMock<Network::MockConnection> conn_;
  NiceMock<Network::MockConnectionSocket> socket_;
  NiceMock<Network::MockIoHandle> io_handle_;
  Network::Socket::OptionsSharedPtr options_;
  std::list<Init::TargetHandlePtr> target_handles_;
};

TEST_F(MetadataConfigTest, NpdsConfigSupported) {
  ::cilium::BpfMetadata config{};
  *config.mutable_cilium_config_source() = Cilium::CILIUM_XDS_API_CONFIG;

  EXPECT_NO_THROW(initialize(config));
}

TEST_F(MetadataConfigTest, NprdsIngressUsesEndpointNamedPortsWithoutAnExternalHostMap) {
  ::cilium::BpfMetadata config;
  config.set_is_ingress(true);
  config.mutable_cilium_config_source()->mutable_ads();
  auto mux = std::make_shared<NiceMock<Config::MockGrpcMux>>();
  ON_CALL(context_.server_factory_context_.xds_manager_, adsMux())
      .WillByDefault(testing::Return(mux));
  config_ = std::make_shared<Cilium::BpfMetadata::Config>(config, context_);
  socket_.connection_info_provider_ =
      std::make_shared<Network::ConnectionInfoSetterImpl>(local_address_, remote_address_);
  auto& singletons = context_.server_factory_context_.singletonManager();
  EXPECT_EQ(singletons.getTyped<PolicyHostMap>("cilium_host_map_singleton"), nullptr);
  const auto policy_map = singletons.getTyped<NetworkPolicyMap>("cilium_network_policy_singleton");
  ASSERT_NE(policy_map, nullptr);
  EXPECT_EQ(config_->resolvePolicyInfo(original_dst_address->ip()).identity_, ID::WORLD);

  const std::vector<std::pair<std::string, std::string>> resources{
      {"destination", R"EOF(
peer:
  identity: 222
  ips: [10.2.2.2]
  named_ports: [{name: http, port: 8081}]
)EOF"},
      {"source", R"EOF(
peer:
  identity: 111
  ips: [10.1.1.1]
  named_ports: [{name: source-http, port: 80}]
)EOF"},
      {"source-selector", "selector: {identities: [111]}"},
      {"pod", R"EOF(
endpoint:
  epid: 42
  ips: [10.2.2.2]
  named_ports: [{name: http, port: 80}]
  policy: pod-policy
)EOF"},
      {"pod-policy", R"EOF(
policy:
  ingress_per_port_policies:
  - port: 80
    rules:
    - selectors: [source-selector]
      deny: true
      precedence: 100
  - port_name: http
    rules:
    - selectors: [source-selector]
      precedence: 200
      http_rules:
        http_rules:
        - headers:
          - {name: ":path", exact_match: /allowed}
)EOF"}};
  NetworkPolicyResourceDecoder decoder;
  Config::DecodedResourcesWrapper decoded;
  for (const auto& [name, yaml] : resources) {
    envoy::service::discovery::v3::Resource resource;
    resource.set_name(name);
    resource.set_version("1");
    std::ignore = resource.mutable_resource()->PackFrom(
        TestUtility::parseYaml<::cilium::NetworkPolicyResource>(yaml));
    decoded.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
  }
  auto& callbacks = CiliumTestPeer::subscriptionCallbacks(*policy_map);
  EXPECT_TRUE(callbacks.onConfigUpdate(decoded.refvec_, {}, "1").ok());

  const auto retained = config_->resolvePolicyInfo(original_dst_address->ip());
  EXPECT_EQ(retained.identity_, 222);
  EXPECT_THAT(retained.namedPorts(), testing::ElementsAre(NamedPort{8081, "http"}));

  // Pod ingress must use its Endpoint even when its peer mapping disagrees or is removed.
  for (bool remove_peer : {false, true}) {
    SCOPED_TRACE(remove_peer);
    if (remove_peer) {
      Protobuf::RepeatedPtrField<std::string> removed;
      removed.Add("destination");
      EXPECT_TRUE(callbacks.onConfigUpdate({}, removed, "2").ok());
      EXPECT_EQ(config_->resolvePolicyInfo(original_dst_address->ip()).identity_, ID::WORLD);
    }
    auto socket_metadata = config_->extractSocketMetadata(socket_);
    ASSERT_TRUE(socket_metadata);
    auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
    ASSERT_NE(policy_fs, nullptr);
    EXPECT_EQ(policy_fs->source_identity_, 111);
    AccessLog::Entry log_entry;

    EXPECT_TRUE(policy_fs->enforceNetworkPolicy(conn_, policy_fs->original_destination_, 80, "",
                                                log_entry));
    Http::TestRequestHeaderMapImpl allowed_headers{{":path", "/allowed"}};
    EXPECT_TRUE(policy_fs->enforcePodHTTPPolicy(conn_, policy_fs->original_destination_, 80,
                                                allowed_headers, log_entry));
    Http::TestRequestHeaderMapImpl denied_headers{{":path", "/denied"}};
    EXPECT_FALSE(policy_fs->enforcePodHTTPPolicy(conn_, policy_fs->original_destination_, 80,
                                                 denied_headers, log_entry));
  }
  EXPECT_THAT(retained.namedPorts(), testing::ElementsAre(NamedPort{8081, "http"}));
}

TEST_F(MetadataConfigTest, NprdsEgressNamedPortsUseDestinationPeers) {
  const std::vector<std::pair<std::string, std::string>> resources{
      {"source", "peer: {identity: 111, ips: [10.1.1.1]}"},
      {"destination", R"EOF(
peer:
  identity: 222
  ips: [10.2.2.2]
  named_ports: [{name: http, port: 80}]
)EOF"},
      {"backend", R"EOF(
peer:
  identity: 333
  ips: [10.3.3.3]
  named_ports: [{name: selected-http, port: 8080}]
)EOF"},
      {"destination-selector", "selector: {identities: [222]}"},
      {"backend-selector", "selector: {identities: [333]}"},
      {"pod", R"EOF(
endpoint:
  epid: 42
  ips: [10.1.1.1, "f00d::1:1:1"]
  policy: pod-policy
)EOF"},
      {"pod-policy", R"EOF(
policy:
  egress_per_port_policies:
  - port: 80
    rules:
    - selectors: [destination-selector]
      deny: true
      precedence: 100
  - port_name: http
    rules:
    - selectors: [destination-selector]
      precedence: 200
  - port_name: selected-http
    rules:
    - selectors: [backend-selector]
      precedence: 200
)EOF"}};
  auto mux = std::make_shared<NiceMock<Config::MockGrpcMux>>();
  ON_CALL(context_.server_factory_context_.xds_manager_, adsMux())
      .WillByDefault(testing::Return(mux));
  socket_.connection_info_provider_ =
      std::make_shared<Network::ConnectionInfoSetterImpl>(local_address_, remote_address_);

  for (bool l7lb : {false, true}) {
    SCOPED_TRACE(l7lb);
    ::cilium::BpfMetadata config;
    config.set_is_l7lb(l7lb);
    config.set_use_original_source_address(l7lb);
    config.mutable_cilium_config_source()->mutable_ads();
    config_ = std::make_shared<Cilium::BpfMetadata::Config>(config, context_);
    ASSERT_NE(config_->npmap_, nullptr);
    NetworkPolicyResourceDecoder decoder;
    Config::DecodedResourcesWrapper decoded;
    for (const auto& [name, yaml] : resources) {
      envoy::service::discovery::v3::Resource resource;
      resource.set_name(name);
      resource.set_version("1");
      std::ignore = resource.mutable_resource()->PackFrom(
          TestUtility::parseYaml<::cilium::NetworkPolicyResource>(yaml));
      decoded.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
    }
    EXPECT_TRUE(CiliumTestPeer::subscriptionCallbacks(*config_->npmap_)
                    .onConfigUpdate(decoded.refvec_, {}, "1")
                    .ok());
    auto socket_metadata = config_->extractSocketMetadata(socket_);
    ASSERT_TRUE(socket_metadata);
    auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
    ASSERT_NE(policy_fs, nullptr);
    EXPECT_EQ(policy_fs->original_destination_.identity_, 222);
    ASSERT_NE(policy_fs->original_destination_.named_ports_, nullptr);
    EXPECT_THAT(*policy_fs->original_destination_.named_ports_,
                testing::ElementsAre(NamedPort{80, "http"}));

    AccessLog::Entry log_entry;

    EXPECT_TRUE(policy_fs->enforceNetworkPolicy(conn_, policy_fs->original_destination_, 80, "",
                                                log_entry));
    EXPECT_FALSE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{222}, 80, "", log_entry));
    if (l7lb) {
      const auto backend =
          policy_fs->resolvePolicyInfo(Network::Address::Ipv4Instance("10.3.3.3").ip());
      EXPECT_EQ(backend.identity_, 333);
      EXPECT_TRUE(policy_fs->enforceNetworkPolicy(conn_, backend, 8080, "", log_entry));
      auto backend_with_original_ports = backend;
      backend_with_original_ports.named_ports_ = policy_fs->original_destination_.named_ports_;
      EXPECT_FALSE(
          policy_fs->enforceNetworkPolicy(conn_, backend_with_original_ports, 8080, "", log_entry));
    }
  }
}

TEST_F(MetadataConfigTest, EgressPolicyUsesInitialHostIdentity) {
  ::cilium::BpfMetadata config{};
  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  ASSERT_TRUE(socket_metadata);
  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  ASSERT_NE(nullptr, policy_fs);

  ASSERT_EQ(policy_fs->original_destination_.identity_, 222);
  EXPECT_EQ(nullptr, policy_fs->original_destination_.named_ports_);

  Protobuf::RepeatedPtrField<std::string> removed_resources;
  removed_resources.Add("222");
  ASSERT_TRUE(hostmap->onConfigUpdate({}, removed_resources, "2").ok());
  const auto current_destination = policy_fs->resolvePolicyInfo(original_dst_address->ip());
  ASSERT_NE(policy_fs->original_destination_.identity_, current_destination.identity_);

  AccessLog::Entry log_entry;
  EXPECT_TRUE(
      policy_fs->enforceNetworkPolicy(conn_, policy_fs->original_destination_, 80, "", log_entry));
  EXPECT_FALSE(policy_fs->enforceNetworkPolicy(conn_, current_destination, 80, "", log_entry));
}

TEST_F(MetadataConfigTest, IngressPolicyUsesSourceIdentity) {
  ::cilium::BpfMetadata config{};
  config.set_is_ingress(true);
  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  ASSERT_TRUE(socket_metadata);
  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  ASSERT_NE(nullptr, policy_fs);

  ASSERT_TRUE(policy_fs->ingress_);
  ASSERT_EQ(policy_fs->source_identity_, 111);
  ASSERT_EQ(policy_fs->original_destination_.identity_, 222);
  EXPECT_EQ(nullptr, policy_fs->original_destination_.named_ports_);

  AccessLog::Entry log_entry;
  EXPECT_TRUE(
      policy_fs->enforceNetworkPolicy(conn_, policy_fs->original_destination_, 80, "", log_entry));
}

TEST_F(MetadataConfigTest, EmptyConfig) {
  ::cilium::BpfMetadata config{};

  EXPECT_NO_THROW(initialize(config));
}

TEST_F(MetadataConfigTest, InvalidL7lbConfig) {
  ::cilium::BpfMetadata config{};
  config.set_is_ingress(true);
  config.set_is_l7lb(true);

  EXPECT_THROW_WITH_MESSAGE(initialize(config), EnvoyException,
                            "cilium.bpf_metadata: is_l7lb may not be set with is_ingress");
}

TEST_F(MetadataConfigTest, InvalidIngressIpv4Address) {
  ::cilium::BpfMetadata config{};
  config.set_ipv4_source_address("invalid");

  EXPECT_THROW_WITH_MESSAGE(
      initialize(config), EnvoyException,
      "cilium.bpf_metadata: ipv4_source_address is not an IPv4 address: invalid");
}

TEST_F(MetadataConfigTest, InvalidIngressIpv6Address) {
  ::cilium::BpfMetadata config{};
  config.set_ipv6_source_address("invalid");

  EXPECT_THROW_WITH_MESSAGE(
      initialize(config), EnvoyException,
      "cilium.bpf_metadata: ipv6_source_address is not an IPv6 address: invalid");
}

TEST_F(MetadataConfigTest, EastWestL7LbConfig) {
  ::cilium::BpfMetadata config{};
  config.set_use_original_source_address(true);
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("127.0.0.1");
  config.set_ipv6_source_address("::1");

  EXPECT_NO_THROW(initialize(config));
}

TEST_F(MetadataConfigTest, NorthSouthL7LbConfig) {
  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("127.0.0.1");
  config.set_ipv6_source_address("::1");

  EXPECT_NO_THROW(initialize(config));
}

// LEGACY N/S without policy enforcement
TEST_F(MetadataConfigTest, NorthSouthL7LbMetadata) {
  // Use external remote address
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.1.1", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("", policy_fs->pod_ip_);
  EXPECT_EQ("", policy_fs->ingress_policy_name_);
  EXPECT_EQ(0, policy_fs->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

TEST_F(MetadataConfigTest, NorthSouthL7LbMetadataMixedSourceAndDestinationFamily) {
  // Use external IPv6 remote address, as seen after a TCP load-balancer forwards
  // an IPv6 client address via PROXY protocol to an IPv4-only node path.
  remote_address_ =
      std::make_shared<Network::Address::Ipv6Instance>("2003:fa:c701:ff01::10f6", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("", policy_fs->pod_ip_);
  EXPECT_EQ("", policy_fs->ingress_policy_name_);
  EXPECT_EQ(0, policy_fs->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ(nullptr, source_addresses_socket_option->ipv6_source_address_);

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark.
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

TEST_F(MetadataConfigTest, NorthSouthL7LbIngressEnforcedMetadata) {
  // Use external remote address
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.1.1", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");
  config.set_enforce_policy_on_l7lb(true);
  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("", policy_fs->pod_ip_);
  EXPECT_EQ("10.1.1.42", policy_fs->ingress_policy_name_);
  EXPECT_EQ(12345678, policy_fs->ingress_source_identity_);

  AccessLog::Entry log_entry;
  log_entry.entry_.set_policy_name("pod");

  // Expect policy accepts security ID 12345678 on ingress on port 80
  EXPECT_TRUE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{12345678}, 80, "", log_entry));
  EXPECT_NE("pod", log_entry.entry_.policy_name());

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

TEST_F(MetadataConfigTest, NorthSouthL7LbEgressHTTPPolicyWithoutIngressHTTPRules) {
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.1.1", 12345);
  policy_config = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.1.42" ]
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 12345678 ]
  egress_per_port_policies:
  - port: 8080
    rules:
    - remote_policies: [ 222 ]
      http_rules:
        http_rules:
        - headers:
          - name: ":path"
            string_match:
              exact: "/allowed"
)EOF";

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_enforce_policy_on_l7lb(true);
  ASSERT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  ASSERT_TRUE(socket_metadata);
  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  ASSERT_NE(nullptr, policy_fs);

  AccessLog::Entry network_log_entry;
  ASSERT_TRUE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{222}, 8080, "", network_log_entry));

  const struct {
    const char* path;
    bool allowed;
  } cases[] = {
      {"/allowed", true},
      {"/denied", false},
  };
  for (const auto& test_case : cases) {
    SCOPED_TRACE(test_case.path);
    Http::TestRequestHeaderMapImpl headers{{":method", "GET"}, {":path", test_case.path}};
    AccessLog::Entry log_entry;
    EXPECT_EQ(test_case.allowed, policy_fs->enforceIngressHTTPPolicy(conn_, PolicyInfo{222}, 8080,
                                                                     headers, log_entry));
  }
}

TEST_F(MetadataConfigTest, NorthSouthL7LbPodAndIngressEnforcedMetadata) {
  // Use external remote address
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.1.1", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");
  config.set_enforce_policy_on_l7lb(true);

  std::string extra_host_map_config = R"EOF(- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 9999
  host_addresses: [ "192.168.1.1" ]
)EOF";

  std::string extra_policy_config = R"EOF(- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '192.168.1.1'
  - 'face:192:168:1:1'
  endpoint_id: 3000
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 222, 333 ]
)EOF";

  EXPECT_NO_THROW(initialize(config, extra_host_map_config, extra_policy_config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("192.168.1.1", policy_fs->pod_ip_);
  EXPECT_EQ("10.1.1.42", policy_fs->ingress_policy_name_);
  EXPECT_EQ(9999, policy_fs->ingress_source_identity_);

  AccessLog::Entry log_entry;
  log_entry.entry_.set_policy_name("pod");

  // Expect pod policy denies security ID 12345678 on port 80 (only 222 allowed)
  EXPECT_FALSE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{12345678}, 80, "", log_entry));
  EXPECT_EQ("pod", log_entry.entry_.policy_name());

  // Expect pod policy allows egress to security ID 222 on port 80
  // Ingress policy allows ingress from 9999 (pod's security ID)
  // Ingress policy allows 222 egress
  EXPECT_TRUE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{222}, 80, "", log_entry));
  EXPECT_NE("pod", log_entry.entry_.policy_name());

  // Expect pod policy allows egress to security ID 333 on port 80
  // Ingress policy allows ingress from 9999
  // Ingress policy denies 333 egress
  EXPECT_FALSE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{333}, 80, "", log_entry));
  EXPECT_NE("pod", log_entry.entry_.policy_name());

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

TEST_F(MetadataConfigTest, NorthSouthL7LbIngressEnforcedCIDRMetadata) {
  // Use external remote address
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.2.1", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");
  config.set_enforce_policy_on_l7lb(true);
  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("", policy_fs->pod_ip_);
  EXPECT_EQ("10.1.1.42", policy_fs->ingress_policy_name_);
  EXPECT_EQ(2, policy_fs->ingress_source_identity_);

  AccessLog::Entry log_entry;
  log_entry.entry_.set_policy_name("pod");

  // Expect policy does not accept security ID 2 on port 80
  EXPECT_FALSE(policy_fs->enforceNetworkPolicy(conn_, PolicyInfo{2}, 80, "", log_entry));
  EXPECT_NE("pod", log_entry.entry_.policy_name());

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

// Use external remote address, but config says to use original source address
TEST_F(MetadataConfigTest, ExternalUseOriginalSourceL7LbMetadata) {
  remote_address_ = std::make_shared<Network::Address::Ipv4Instance>("192.168.1.1", 12345);

  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_use_original_source_address(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_FALSE(socket_metadata);
}

TEST_F(MetadataConfigTest, EastWestL7LbMetadata) {
  ::cilium::BpfMetadata config{};
  config.set_use_original_source_address(true);
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(111, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("10.1.1.1", policy_fs->pod_ip_);
  EXPECT_EQ("", policy_fs->ingress_policy_name_);

  // test with 1 second SO_LINGER option
  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ("10.1.1.1:41234", source_addresses_socket_option->original_source_address_->asString());
  EXPECT_EQ("10.1.1.1:41234", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::1:1:1]:41234",
            source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Endpoint's ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0900 &&
              (cilium_mark_socket_option->mark_ >> 16) == 2048);
}

// When original source is not configured to be used, east/west traffic takes the north/south path
// but retains local pod's IP as the "policy name" it found.
TEST_F(MetadataConfigTest, EastWestL7LbMetadataNoOriginalSource) {
  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  auto policy_fs = socket_metadata->buildCiliumPolicyFilterState();
  EXPECT_NE(nullptr, policy_fs);

  EXPECT_EQ(8, policy_fs->source_identity_);
  EXPECT_EQ(false, policy_fs->ingress_);
  EXPECT_EQ(true, policy_fs->is_l7lb_);
  EXPECT_EQ(80, policy_fs->port_);
  EXPECT_EQ("10.1.1.1", policy_fs->pod_ip_);
  EXPECT_EQ("", policy_fs->ingress_policy_name_);
  EXPECT_EQ(0, policy_fs->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption(-1);
  EXPECT_NE(nullptr, source_addresses_socket_option);
  EXPECT_EQ(-1, source_addresses_socket_option->linger_time_);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

TEST_F(MetadataConfigTest, RestoreLocalAddress) {
  ::cilium::BpfMetadata config{};

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  EXPECT_NE(socket_.connectionInfoProvider().localAddress(), original_dst_address);
  EXPECT_FALSE(socket_.connectionInfoProvider().localAddressRestored());

  socket_metadata->configureOriginalDstAddress(socket_);

  EXPECT_EQ(socket_.connectionInfoProvider().localAddress(), original_dst_address);
  EXPECT_TRUE(socket_.connectionInfoProvider().localAddressRestored());
}

} // namespace
} // namespace Cilium
} // namespace Envoy
