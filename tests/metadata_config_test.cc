#include <gmock/gmock-actions.h>
#include <gmock/gmock-spec-builders.h>
#include <spdlog/common.h>

#include <cstdint>
#include <list>
#include <memory>
#include <utility>
#include <vector>

#include "envoy/api/api.h"
#include "envoy/common/exception.h"
#include "envoy/filesystem/watcher.h"
#include "envoy/init/target.h"
#include "envoy/init/watcher.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/network/socket.h"

#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/address_impl.h"
#include "source/common/network/socket_impl.h"
#include "source/common/stats/isolated_store_impl.h"

#include "test/mocks/filesystem/mocks.h"
#include "test/mocks/network/io_handle.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/server/listener_factory_context.h"
#include "test/mocks/server/transport_socket_factory_context.h"
#include "test/test_common/utility.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/bpf_metadata.h"
#include "gtest/gtest.h"
#include "tests/bpf_metadata.h"

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

    ON_CALL(context_, getTransportSocketFactoryContext())
        .WillByDefault(ReturnRef(transport_socket_factory_context_));

    ON_CALL(context_.server_factory_context_, api()).WillByDefault(testing::ReturnRef(*api_));

    ON_CALL(context_.server_factory_context_.dispatcher_, createFilesystemWatcher_())
        .WillByDefault(Invoke([]() -> Filesystem::Watcher* {
          auto watcher = new Filesystem::MockWatcher();
          EXPECT_CALL(*watcher, addWatch(_, Filesystem::Watcher::Events::MovedTo, _))
              .WillOnce(Invoke([](absl::string_view, uint32_t, Filesystem::Watcher::OnChangedCb) {
                return absl::OkStatus();
              }));
          Mock::AllowLeak(watcher);
          return watcher;
        }));
    ON_CALL(context_.init_manager_, add(_))
        .WillByDefault(Invoke([this](const Init::Target& target) {
          target_handles_.push_back(target.createHandle("test"));
        }));
    ON_CALL(context_.init_manager_, initialize(_))
        .WillByDefault(Invoke([this](const Init::Watcher& watcher) {
          for (auto& handle_ : target_handles_) {
            handle_->initialize(watcher);
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

    ON_CALL(io_handle_, localAddress()).WillByDefault(testing::Return(original_dst_address));
    EXPECT_EQ(&io_handle_, &socket_.ioHandle());
    auto addr = socket_.ioHandle().localAddress().get();
    EXPECT_NE(nullptr, addr);

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
    - remote_policies: [ 12345678 ]
  egress_per_port_policies: {}
)EOF";
  }
  ~MetadataConfigTest() override {
    hostmap.reset();
    npmap.reset();
  }

  void SetUp() override {}

  void initialize(const ::cilium::BpfMetadata& config) {
    socket_.connection_info_provider_ =
        std::make_shared<Network::ConnectionInfoSetterImpl>(local_address_, remote_address_);

    initTestMaps(context_);

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
  NiceMock<Network::MockConnectionSocket> socket_;
  NiceMock<Network::MockIoHandle> io_handle_;
  Network::Socket::OptionsSharedPtr options_;
  std::list<Init::TargetHandlePtr> target_handles_;
};

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

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_NE(nullptr, policy_socket_option);

  EXPECT_EQ(8, policy_socket_option->source_identity_);
  EXPECT_EQ(false, policy_socket_option->ingress_);
  EXPECT_EQ(true, policy_socket_option->is_l7lb_);
  EXPECT_EQ(80, policy_socket_option->port_);
  EXPECT_EQ("10.1.1.42", policy_socket_option->pod_ip_);
  EXPECT_EQ(0, policy_socket_option->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption();
  EXPECT_NE(nullptr, source_addresses_socket_option);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
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

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_NE(nullptr, policy_socket_option);

  EXPECT_EQ(8, policy_socket_option->source_identity_);
  EXPECT_EQ(false, policy_socket_option->ingress_);
  EXPECT_EQ(true, policy_socket_option->is_l7lb_);
  EXPECT_EQ(80, policy_socket_option->port_);
  EXPECT_EQ("10.1.1.42", policy_socket_option->pod_ip_);
  EXPECT_EQ(12345678, policy_socket_option->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption();
  EXPECT_NE(nullptr, source_addresses_socket_option);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);

  // Expect policy accepts security ID 12345678 on ingress on port 80
  auto port_policy = policy_socket_option->getPolicy()->findPortPolicy(true, 80);
  EXPECT_TRUE(port_policy.allowed(12345678, ""));
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

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_NE(nullptr, policy_socket_option);

  EXPECT_EQ(8, policy_socket_option->source_identity_);
  EXPECT_EQ(false, policy_socket_option->ingress_);
  EXPECT_EQ(true, policy_socket_option->is_l7lb_);
  EXPECT_EQ(80, policy_socket_option->port_);
  EXPECT_EQ("10.1.1.42", policy_socket_option->pod_ip_);
  EXPECT_EQ(2, policy_socket_option->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption();
  EXPECT_NE(nullptr, source_addresses_socket_option);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress security ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);

  // Expect policy does not accept security ID 2 on ingress on port 80
  auto port_policy = policy_socket_option->getPolicy()->findPortPolicy(true, 80);
  EXPECT_FALSE(port_policy.allowed(2, ""));
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

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_EQ(nullptr, policy_socket_option);
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

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_NE(nullptr, policy_socket_option);

  EXPECT_EQ(111, policy_socket_option->source_identity_);
  EXPECT_EQ(false, policy_socket_option->ingress_);
  EXPECT_EQ(true, policy_socket_option->is_l7lb_);
  EXPECT_EQ(80, policy_socket_option->port_);
  EXPECT_EQ("10.1.1.1", policy_socket_option->pod_ip_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption();
  EXPECT_NE(nullptr, source_addresses_socket_option);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
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
TEST_F(MetadataConfigTest, EastWestL7LbMetadataNoOriginalSource) {
  ::cilium::BpfMetadata config{};
  config.set_is_l7lb(true);
  config.set_ipv4_source_address("10.1.1.42");
  config.set_ipv6_source_address("face::42");

  EXPECT_NO_THROW(initialize(config));

  auto socket_metadata = config_->extractSocketMetadata(socket_);
  EXPECT_TRUE(socket_metadata);

  const auto policy_socket_option = socket_metadata->buildCiliumPolicySocketOption();
  EXPECT_NE(nullptr, policy_socket_option);

  EXPECT_EQ(8, policy_socket_option->source_identity_);
  EXPECT_EQ(false, policy_socket_option->ingress_);
  EXPECT_EQ(true, policy_socket_option->is_l7lb_);
  EXPECT_EQ(80, policy_socket_option->port_);
  EXPECT_EQ("10.1.1.42", policy_socket_option->pod_ip_);
  EXPECT_EQ(0, policy_socket_option->ingress_source_identity_);

  auto source_addresses_socket_option = socket_metadata->buildSourceAddressSocketOption();
  EXPECT_NE(nullptr, source_addresses_socket_option);

  EXPECT_EQ(nullptr, source_addresses_socket_option->original_source_address_);
  EXPECT_EQ("10.1.1.42:0", source_addresses_socket_option->ipv4_source_address_->asString());
  EXPECT_EQ("[face::42]:0", source_addresses_socket_option->ipv6_source_address_->asString());

  auto cilium_mark_socket_option = socket_metadata->buildCiliumMarkSocketOption();
  EXPECT_NE(nullptr, cilium_mark_socket_option);

  // Check that Ingress ID is used in the socket mark
  EXPECT_TRUE((cilium_mark_socket_option->mark_ & 0xffff) == 0x0B00 &&
              (cilium_mark_socket_option->mark_ >> 16) == 8);
}

} // namespace
} // namespace Cilium
} // namespace Envoy
