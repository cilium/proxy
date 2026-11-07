#include <gmock/gmock-spec-builders.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/common.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/optref.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/init/manager.h"
#include "envoy/server/factory_context.h"
#include "envoy/service/discovery/v3/discovery.pb.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"

#include "source/common/common/assert.h"
#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/common/regex.h"
#include "source/common/config/decoded_resource_impl.h"
#include "source/common/init/target_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/secret/sds_api.h" // NOLINT

#include "test/common/stats/stat_test_utility.h"
#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/admin.h"
#include "test/mocks/server/factory_context.h"
#include "test/mocks/thread_local/mocks.h"
#include "test/test_common/utility.h"

#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/grpc_subscription.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "cilium/policy_id.h"
#include "tests/cilium_test_peer.h"
#include "source/common/network/utility.h"

namespace Envoy {
namespace Cilium {

// Cilium XDS API config source. Used for all Cilium XDS.
extern const envoy::config::core::v3::ConfigSource CILIUM_XDS_API_CONFIG;

// Creates a real SdsApi provider, registering it with the init manager if one was supplied.
template <typename SdsApi>
auto createSdsSecretProvider(const envoy::config::core::v3::ConfigSource& sds_config_source,
                             const std::string& config_name,
                             Server::Configuration::ServerFactoryContext& server_context,
                             OptRef<Init::Manager> init_manager) {
  auto secret_provider =
      SdsApi::create(server_context, sds_config_source, config_name, []() {}, false);
  if (init_manager.has_value()) {
    init_manager->add(*secret_provider->initTarget());
  }
  return secret_provider;
}

// findOrCreate*Provider signatures are not uniform: TlsCertificate and GenericSecret take an
// OptRef<Init::Manager> and a bool warm, the rest take Init::Manager&.
// Hence one macro per shape, all sharing createSdsSecretProvider() above.
#define ON_CALL_SDS_SECRET_PROVIDER(SECRET_MANAGER, PROVIDER_TYPE, API_TYPE)                       \
  ON_CALL(SECRET_MANAGER, findOrCreate##PROVIDER_TYPE##Provider(_, _, _, _))                       \
      .WillByDefault(Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,     \
                               const std::string& config_name,                                     \
                               Server::Configuration::ServerFactoryContext& server_context,        \
                               Init::Manager& init_manager) {                                      \
        return createSdsSecretProvider<Secret::API_TYPE##SdsApi>(                                  \
            sds_config_source, config_name, server_context, makeOptRef(init_manager));             \
      }))

#define ON_CALL_SDS_SECRET_PROVIDER_OPT_INIT(SECRET_MANAGER, PROVIDER_TYPE, API_TYPE)              \
  ON_CALL(SECRET_MANAGER, findOrCreate##PROVIDER_TYPE##Provider(_, _, _, _, _))                    \
      .WillByDefault(Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,     \
                               const std::string& config_name,                                     \
                               Server::Configuration::ServerFactoryContext& server_context,        \
                               OptRef<Init::Manager> init_manager, bool /*warm*/) {                \
        return createSdsSecretProvider<Secret::API_TYPE##SdsApi>(sds_config_source, config_name,   \
                                                                 server_context, init_manager);    \
      }))

namespace {

envoy::config::core::v3::ConfigSource configSourceForUseDeltaXds(bool use_delta_xds) {
  auto config_source = CILIUM_XDS_API_CONFIG;
  config_source.mutable_api_config_source()->set_api_type(
      use_delta_xds ? envoy::config::core::v3::ApiConfigSource::DELTA_GRPC
                    : envoy::config::core::v3::ApiConfigSource::GRPC);
  return config_source;
}

struct FakeSubscriptionState {
  int start_calls_{0};
  std::vector<std::vector<std::string>> start_resources_;
};

class FakeSubscription : public Envoy::Config::Subscription {
public:
  explicit FakeSubscription(std::shared_ptr<FakeSubscriptionState> state)
      : state_(std::move(state)) {}

  void start(const absl::flat_hash_set<std::string>& resource_names) override {
    ++state_->start_calls_;
    auto& started = state_->start_resources_.emplace_back();
    started.insert(started.end(), resource_names.begin(), resource_names.end());
    std::sort(started.begin(), started.end());
  }

  void updateResourceInterest(const absl::flat_hash_set<std::string>&) override {}
  void requestOnDemandUpdate(const absl::flat_hash_set<std::string>&) override {}
  void accept(const absl::flat_hash_set<std::string>&) override {}

private:
  std::shared_ptr<FakeSubscriptionState> state_;
};

} // namespace

class CiliumNetworkPolicyTest : public ::testing::Test {
protected:
  CiliumNetworkPolicyTest() {
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumNetworkPolicyTest() override = default;

  void SetUp() override {
    // Mock SDS secrets with a real implementation, which will not return anything if there is no
    // SDS server. This is only useful for testing functionality with a missing secret.
    ON_CALL(factory_context_.server_factory_context_, secretManager())
        .WillByDefault(ReturnRef(secret_manager_));

    ON_CALL_SDS_SECRET_PROVIDER_OPT_INIT(secret_manager_, TlsCertificate, TlsCertificate);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, CertificateValidationContext,
                                CertificateValidationContext);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, TlsSessionTicketKeysContext, TlsSessionTicketKeys);
    ON_CALL_SDS_SECRET_PROVIDER_OPT_INIT(secret_manager_, GenericSecret, GenericSecret);

    bool use_delta = useDeltaXds();
    configured_use_delta_xds_ = use_delta;
    policy_map_ = std::make_shared<NetworkPolicyMap>(factory_context_,
                                                     configSourceForUseDeltaXds(use_delta), false);
    CiliumTestPeer::setSubscription(
        *policy_map_, nullptr, use_delta ? NetworkPolicyResourceTypeUrl : NetworkPolicyTypeUrl);
    setSubscriptionFactoryForTest([](bool) {
      return std::make_unique<FakeSubscription>(std::make_shared<FakeSubscriptionState>());
    });
  }

  void TearDown() override {
    ASSERT(policy_map_.use_count() == 1);
    policy_map_.reset();
  }

  virtual bool useDeltaXds() const { return false; }

  Envoy::Config::SubscriptionCallbacks& subscriptionCallbacks() const {
    return CiliumTestPeer::subscriptionCallbacks(*policy_map_);
  }

  std::string updateFromYaml(const std::string& config) {
    if (CiliumTestPeer::subscriptionTypeUrl(*policy_map_) == NetworkPolicyResourceTypeUrl) {
      EXPECT_TRUE(subscriptionCallbacks().onConfigUpdate({}, "").ok());
      onSubscriptionConnectedForTest();
    }
    envoy::service::discovery::v3::DiscoveryResponse message;
    MessageUtil::loadFromYaml(config, message, ProtobufMessage::getNullValidationVisitor());
    NetworkPolicyDecoder network_policy_decoder;
    const auto decoded_resources_or_error = Config::DecodedResourcesWrapper::create(
        network_policy_decoder, message.resources(), message.version_info());
    THROW_IF_NOT_OK_REF(decoded_resources_or_error.status());
    const auto decoded_resources = std::move(decoded_resources_or_error.value().get());

    EXPECT_TRUE(subscriptionCallbacks()
                    .onConfigUpdate(decoded_resources->refvec_, message.version_info())
                    .ok());
    return message.version_info();
  }

  absl::Status nprdsUpdateFromYaml(const std::string& config, bool sotw) {
    envoy::service::discovery::v3::DeltaDiscoveryResponse message;
    MessageUtil::loadFromYaml(config, message, ProtobufMessage::getNullValidationVisitor());
    NetworkPolicyResourceDecoder decoder;
    Config::DecodedResourcesWrapper resources;
    for (const auto& resource : message.resources()) {
      resources.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
    }
    return sotw ? subscriptionCallbacks().onConfigUpdate(resources.refvec_,
                                                         message.system_version_info())
                : subscriptionCallbacks().onConfigUpdate(resources.refvec_,
                                                         message.removed_resources(),
                                                         message.system_version_info());
  }

  void deltaUpdateFromYaml(const std::string& config) {
    THROW_IF_NOT_OK(nprdsUpdateFromYaml(config, false));
  }

  void applyResourceUpdate(
      const std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>& resources,
      const std::vector<std::string>& removed, bool delta) {
    NetworkPolicyResourceDecoder decoder;
    Config::DecodedResourcesWrapper decoded;
    for (const auto& [name, config] : resources) {
      envoy::service::discovery::v3::Resource resource;
      resource.set_name(name);
      resource.set_version("1");
      std::ignore = resource.mutable_resource()->PackFrom(config);
      decoded.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
    }
    if (delta) {
      Protobuf::RepeatedPtrField<std::string> removed_resources;
      for (const auto& name : removed) {
        *removed_resources.Add() = name;
      }
      THROW_IF_NOT_OK(
          subscriptionCallbacks().onConfigUpdate(decoded.refvec_, removed_resources, "1"));
    } else {
      EXPECT_TRUE(removed.empty());
      THROW_IF_NOT_OK(subscriptionCallbacks().onConfigUpdate(decoded.refvec_, "1"));
    }
  }

  testing::AssertionResult validate(const std::string& pod_ip, const std::string& expected) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);
    auto str = policy.string();
    if (str != expected) {
      return testing::AssertionFailure() << "Policy:\n"
                                         << str << "Does not match expected:\n"
                                         << expected;
    }
    return testing::AssertionSuccess();
  }

  testing::AssertionResult allowed(const PortPolicy& port_policy, uint64_t remote_id,
                                   Http::TestRequestHeaderMapImpl&& headers) {
    if (!port_policy.allowed(proxy_id_, remote_id, "")) {
      return testing::AssertionFailure();
    }
    if (!port_policy.hasHttpRules()) {
      return testing::AssertionSuccess();
    }
    Cilium::AccessLog::Entry log_entry;
    return port_policy.allowed(proxy_id_, remote_id, headers, log_entry)
               ? testing::AssertionSuccess()
               : testing::AssertionFailure();
  }

  testing::AssertionResult egressAllowed(const std::string& pod_ip, uint32_t remote_id,
                                         uint16_t port, NamedPorts destination_named_ports) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);
    NamedPortsConstSharedPtr named_ports =
        destination_named_ports.empty()
            ? nullptr
            : std::make_shared<const NamedPorts>(std::move(destination_named_ports));
    auto port_policy = policy.findEgressPortPolicy(port, named_ports);
    return port_policy.allowed(proxy_id_, remote_id, "") ? testing::AssertionSuccess()
                                                         : testing::AssertionFailure();
  }
  testing::AssertionResult ingressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                          uint16_t port,
                                          Http::TestRequestHeaderMapImpl&& headers = {}) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);
    return allowed(policy.findIngressPortPolicy(port), remote_id, std::move(headers));
  }
  testing::AssertionResult egressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                         uint16_t port,
                                         Http::TestRequestHeaderMapImpl&& headers = {}) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);
    return allowed(policy.findEgressPortPolicy(port, nullptr), remote_id, std::move(headers));
  }

  testing::AssertionResult tlsAllowed(bool ingress, const std::string& pod_ip, uint64_t remote_id,
                                      uint16_t port, absl::string_view sni,
                                      bool& tls_socket_required, bool& raw_socket_allowed) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);

    auto port_policy =
        ingress ? policy.findIngressPortPolicy(port) : policy.findEgressPortPolicy(port, nullptr);
    const Envoy::Ssl::ContextConfig* config = nullptr;

    // TLS context lookup does not check SNI
    tls_socket_required = false;
    raw_socket_allowed = false;
    Envoy::Ssl::ContextSharedPtr ctx =
        !ingress
            ? port_policy.getClientTlsContext(proxy_id_, remote_id, sni, config, raw_socket_allowed)
            : port_policy.getServerTlsContext(proxy_id_, remote_id, sni, config,
                                              raw_socket_allowed);

    // Check the network verdict separately from TLS context selection.
    bool allowed = port_policy.allowed(proxy_id_, remote_id, sni);

    // if connection is allowed without TLS socket then TLS context is not required
    if (raw_socket_allowed) {
      EXPECT_TRUE(ctx == nullptr && config == nullptr);
      tls_socket_required = false;
    }

    // if TLS config or context is returned then connection is not allowed without TLS socket
    if (ctx != nullptr || config != nullptr) {
      EXPECT_FALSE(raw_socket_allowed);
      tls_socket_required = true;
    }

    // config must exist if ctx is returned
    if (ctx != nullptr) {
      EXPECT_TRUE(config != nullptr);
    }

    EXPECT_TRUE(allowed == (tls_socket_required || raw_socket_allowed));

    if (!allowed) {
      return testing::AssertionFailure() << pod_ip << " policy not allowing id " << remote_id
                                         << " on port " << port << " with SNI \"" << sni << "\"";
    }

    // sanity check
    EXPECT_TRUE(!(tls_socket_required && raw_socket_allowed) &&
                (tls_socket_required || raw_socket_allowed));

    if (raw_socket_allowed) {
      return testing::AssertionSuccess()
             << pod_ip << " policy allows id " << remote_id << " on port " << port << " with SNI \""
             << sni << "\" without TLS socket";
    }

    if (tls_socket_required && ctx != nullptr) {
      return testing::AssertionSuccess()
             << pod_ip << " policy allows id " << remote_id << " on port " << port << " with SNI \""
             << sni << "\" with TLS socket";
    }

    if (tls_socket_required && ctx == nullptr) {
      return testing::AssertionSuccess()
             << pod_ip << " policy allows id " << remote_id << " on port " << port << " with SNI \""
             << sni << "\" but missing TLS context";
    }

    return testing::AssertionFailure();
  }

  testing::AssertionResult tlsIngressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                             uint16_t port, absl::string_view sni,
                                             bool& tls_socket_required, bool& raw_socket_allowed) {
    return tlsAllowed(true, pod_ip, remote_id, port, sni, tls_socket_required, raw_socket_allowed);
  }

  testing::AssertionResult tlsEgressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                            uint16_t port, absl::string_view sni,
                                            bool& tls_socket_required, bool& raw_socket_allowed) {
    return tlsAllowed(false, pod_ip, remote_id, port, sni, tls_socket_required, raw_socket_allowed);
  }

  const Ssl::ContextConfig* tlsContextConfig(const PolicyInstance& policy, bool ingress,
                                             uint64_t remote_id, uint16_t port) {
    auto port_policy =
        ingress ? policy.findIngressPortPolicy(port) : policy.findEgressPortPolicy(port, nullptr);
    const Ssl::ContextConfig* config = nullptr;
    bool raw_socket_allowed = false;
    if (ingress) {
      static_cast<void>(
          port_policy.getServerTlsContext(proxy_id_, remote_id, "", config, raw_socket_allowed));
    } else {
      static_cast<void>(
          port_policy.getClientTlsContext(proxy_id_, remote_id, "", config, raw_socket_allowed));
    }
    EXPECT_FALSE(raw_socket_allowed);
    EXPECT_NE(config, nullptr);
    return config;
  }

  std::string updatesRejectedStatName() {
    return CiliumTestPeer::policyStats(*policy_map_).updates_rejected_.name();
  }

  auto policyShared(const std::string& pod_ip) const {
    return CiliumTestPeer::policyShared(*policy_map_, pod_ip);
  }

  void resetStreamForTest() {
    CiliumTestPeer::resetStream(*policy_map_);
    CiliumTestPeer::setSubscription(
        *policy_map_, nullptr, useDeltaXds() ? NetworkPolicyResourceTypeUrl : NetworkPolicyTypeUrl);
  }

  bool configuredUseDeltaXds() const { return configured_use_delta_xds_; }

  void setPolicyConfig(bool use_delta_xds) const {
    configured_use_delta_xds_ = use_delta_xds;
    policy_map_->configure(configSourceForUseDeltaXds(use_delta_xds));
  }

  void startManagedSubscriptionForTest() {
    CiliumTestPeer::subscribe(*policy_map_);
    CiliumTestPeer::start(*policy_map_);
  }

  void setSubscriptionFactoryForTest(ManagedGrpcSubscription::SubscriptionFactoryForTest factory) {
    CiliumTestPeer::setSubscriptionFactory(
        *policy_map_, [this, factory = std::move(factory)](bool use_delta_xds) mutable {
          subscription_use_delta_xds_ = use_delta_xds;
          return factory(use_delta_xds);
        });
  }
  void onSubscriptionConnectedForTest() {
    CiliumTestPeer::onStreamEvent(*policy_map_, Config::GrpcMuxStreamEvent::Established);
  }
  void onSubscriptionTransportCloseForTest() {
    CiliumTestPeer::onStreamEvent(*policy_map_, Config::GrpcMuxStreamEvent::Closed);
  }
  bool subscriptionUseDeltaXdsForTest() const { return subscription_use_delta_xds_; }
  bool subscriptionConnectedForTest() const { return CiliumTestPeer::connected(*policy_map_); }

  NiceMock<Server::Configuration::MockFactoryContext> factory_context_;
  NiceMock<Secret::MockSecretManager> secret_manager_;
  std::shared_ptr<NetworkPolicyMap> policy_map_;
  NiceMock<Stats::TestUtil::TestStore> store_;
  uint16_t proxy_id_ = 42;
  mutable bool configured_use_delta_xds_{false};
  mutable bool subscription_use_delta_xds_{false};
};

class CiliumNetworkPolicyDeltaTest : public CiliumNetworkPolicyTest {
protected:
  bool useDeltaXds() const override { return true; }
};

TEST_F(CiliumNetworkPolicyTest, UpdatesRejectedStatName) {
  EXPECT_EQ("cilium.policy.updates_rejected", updatesRejectedStatName());
}

TEST_F(CiliumNetworkPolicyTest, ManagedSubscriptionSelectsPolicyProtocolForTransport) {
  const struct {
    const char* name;
    bool ads;
    bool delta;
  } test_cases[] = {
      {"split SotW", false, false},
      {"split Delta", false, true},
      {"ADS SotW", true, false},
      {"ADS Delta", true, true},
  };
  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.name);
    auto config_source = configSourceForUseDeltaXds(test_case.delta);
    // Explicit sources must ignore the bootstrap ADS transport.
    const bool ads_delta = test_case.ads ? test_case.delta : !test_case.delta;
    factory_context_.server_factory_context_.bootstrap_.mutable_dynamic_resources()
        ->mutable_ads_config()
        ->set_api_type(ads_delta ? envoy::config::core::v3::ApiConfigSource::DELTA_GRPC
                                 : envoy::config::core::v3::ApiConfigSource::GRPC);
    if (test_case.ads) {
      config_source.mutable_ads();
    }
    CiliumTestPeer::setSubscription(*policy_map_, nullptr);
    policy_map_->configure(config_source);
    auto state = std::make_shared<FakeSubscriptionState>();
    std::vector<bool> created_modes;
    setSubscriptionFactoryForTest(
        [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Config::Subscription> {
          created_modes.push_back(use_delta_xds);
          return std::make_unique<FakeSubscription>(state);
        });

    startManagedSubscriptionForTest();

    EXPECT_THAT(created_modes, testing::ElementsAre(test_case.delta));
    EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_),
              test_case.delta ? NetworkPolicyResourceTypeUrl : NetworkPolicyTypeUrl);
    ASSERT_EQ(state->start_calls_, 1);
    EXPECT_TRUE(state->start_resources_.front().empty());
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, EmptyInitialResponseNegotiatesEachStream) {
  auto state = std::make_shared<FakeSubscriptionState>();
  setSubscriptionFactoryForTest(
      [state](bool) { return std::make_unique<FakeSubscription>(state); });

  const std::string nprds = R"EOF(resources:
- name: policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: endpoint
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: policy}
- name: peer
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    peer: {identity: 43, ips: [10.2.3.4], named_ports: [{name: http, port: 80}]}
)EOF";
  const std::string npds = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_id: 44
  endpoint_ips: [10.1.2.4]
)EOF";
  const auto address = Network::Utility::parseInternetAddressNoThrow("10.2.3.4");
  setPolicyConfig(true);
  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
  ASSERT_TRUE(nprdsUpdateFromYaml(nprds, false).ok());
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // An empty later update does not negotiate again.
  ASSERT_TRUE(nprdsUpdateFromYaml("resources: []", false).ok());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
  ASSERT_TRUE(nprdsUpdateFromYaml(nprds, false).ok());
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  const auto accepted = policyShared("10.1.2.3");
  ASSERT_NE(accepted, nullptr);

  onSubscriptionTransportCloseForTest();
  onSubscriptionConnectedForTest();
  const auto before_fallback = state->start_calls_;
  ASSERT_TRUE(nprdsUpdateFromYaml("resources: []", false).ok());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyTypeUrl);
  EXPECT_EQ(state->start_calls_, before_fallback + 1);
  EXPECT_EQ(policyShared("10.1.2.3"), accepted);
  ASSERT_TRUE(policy_map_->resolvePolicyInfo(address->ip()).has_value());
  EXPECT_EQ(policy_map_->resolvePolicyInfo(address->ip())->identity_, 43);

  // Listener recreation with the same source must not restart negotiation.
  setPolicyConfig(true);
  EXPECT_EQ(state->start_calls_, before_fallback + 1);
  onSubscriptionConnectedForTest();
  updateFromYaml(npds);
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.4"));
  EXPECT_FALSE(policy_map_->resolvePolicyInfo(address->ip()).has_value());
  EXPECT_TRUE(subscriptionCallbacks().onConfigUpdate({}, "2").ok());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyTypeUrl);
  EXPECT_FALSE(policy_map_->exists("10.1.2.4"));

  onSubscriptionTransportCloseForTest();
  onSubscriptionConnectedForTest();
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
  ASSERT_TRUE(nprdsUpdateFromYaml(nprds, false).ok());
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  ASSERT_TRUE(policy_map_->resolvePolicyInfo(address->ip()).has_value());
  EXPECT_EQ(policy_map_->resolvePolicyInfo(address->ip())->identity_, 43);
}

TEST_F(CiliumNetworkPolicyDeltaTest, UnimplementedOnlyFallsBackBeforeAnyResponse) {
  auto state = std::make_shared<FakeSubscriptionState>();
  setSubscriptionFactoryForTest(
      [state](bool) { return std::make_unique<FakeSubscription>(state); });
  for (bool rejected_response : {false, true}) {
    SCOPED_TRACE(rejected_response);
    startManagedSubscriptionForTest();
    onSubscriptionConnectedForTest();
    if (rejected_response) {
      EnvoyException error("invalid NPRDS resource");
      subscriptionCallbacks().onConfigUpdateFailed(
          Config::ConfigUpdateFailureReason::UpdateRejected, &error);
    }
    CiliumTestPeer::onStreamEvent(*policy_map_, Config::GrpcMuxStreamEvent::Unimplemented);
    EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_),
              rejected_response ? NetworkPolicyResourceTypeUrl : NetworkPolicyTypeUrl);
    if (rejected_response) {
      // Empty data after a rejected first response is an ordinary NPRDS update.
      EXPECT_TRUE(subscriptionCallbacks().onConfigUpdate({}, {}, "1").ok());
      EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
    }
  }
}

TEST_F(CiliumNetworkPolicyTest, FailedSubscriptionReplacementKeepsAcceptedProtocol) {
  auto state = std::make_shared<FakeSubscriptionState>();
  bool reject_replacement = false;
  setSubscriptionFactoryForTest([&](bool) -> std::unique_ptr<Config::Subscription> {
    if (reject_replacement) {
      // An ADS mux may already be connected before the new subscription is created.
      onSubscriptionConnectedForTest();
      throw EnvoyException("replacement failed");
    }
    return std::make_unique<FakeSubscription>(state);
  });
  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();

  const std::string policy_yaml = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_id: 42
  endpoint_ips: [10.1.2.3]
)EOF";
  updateFromYaml(policy_yaml);
  const auto accepted_policy = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
  ASSERT_NE(accepted_policy, nullptr);

  reject_replacement = true;
  EXPECT_THROW_WITH_MESSAGE(setPolicyConfig(true), EnvoyException, "replacement failed");
  EXPECT_TRUE(subscriptionConnectedForTest());
  EXPECT_NO_THROW(updateFromYaml(policy_yaml));
  EXPECT_EQ(CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3"), accepted_policy);

  reject_replacement = false;
  onSubscriptionTransportCloseForTest();
  EXPECT_TRUE(subscriptionUseDeltaXdsForTest());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
  EXPECT_EQ(state->start_calls_, 2);
}

TEST_F(CiliumNetworkPolicyTest,
       TransportChangeFromSotwToDeltaOnHealthySubscriptionRecreatesImmediately) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();
  ASSERT_TRUE(subscriptionConnectedForTest());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyTypeUrl);

  setPolicyConfig(true);

  EXPECT_TRUE(configuredUseDeltaXds());
  EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
  EXPECT_TRUE(subscriptionUseDeltaXdsForTest());
  EXPECT_FALSE(subscriptionConnectedForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(false, true));
  EXPECT_EQ(state->start_calls_, 2);
  EXPECT_TRUE(state->start_resources_.back().empty());
}

TEST_F(CiliumNetworkPolicyTest, TransportChangeFromDeltaToSotwOnHealthySubscriptionWaitsForClose) {
  for (bool ads : {false, true}) {
    SCOPED_TRACE(ads);
    auto config_source = configSourceForUseDeltaXds(true);
    if (ads) {
      config_source.mutable_ads();
      factory_context_.server_factory_context_.bootstrap_.mutable_dynamic_resources()
          ->mutable_ads_config()
          ->set_api_type(envoy::config::core::v3::ApiConfigSource::DELTA_GRPC);
    }
    CiliumTestPeer::setSubscription(*policy_map_, nullptr);
    policy_map_->configure(config_source);
    auto state = std::make_shared<FakeSubscriptionState>();
    std::vector<bool> created_modes;
    setSubscriptionFactoryForTest(
        [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Config::Subscription> {
          created_modes.push_back(use_delta_xds);
          return std::make_unique<FakeSubscription>(state);
        });

    startManagedSubscriptionForTest();
    onSubscriptionConnectedForTest();
    ASSERT_TRUE(subscriptionConnectedForTest());
    ASSERT_TRUE(subscriptionUseDeltaXdsForTest());
    ASSERT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);

    setPolicyConfig(false);

    EXPECT_FALSE(configuredUseDeltaXds());
    EXPECT_TRUE(subscriptionUseDeltaXdsForTest());
    EXPECT_TRUE(subscriptionConnectedForTest());
    EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
    EXPECT_THAT(created_modes, testing::ElementsAre(true));
    EXPECT_EQ(state->start_calls_, 1);

    onSubscriptionTransportCloseForTest();

    EXPECT_FALSE(subscriptionConnectedForTest());
    EXPECT_FALSE(subscriptionUseDeltaXdsForTest());
    EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyTypeUrl);
    EXPECT_THAT(created_modes, testing::ElementsAre(true, false));
    EXPECT_EQ(state->start_calls_, 2);
    EXPECT_TRUE(state->start_resources_.back().empty());

    // Selecting NPDS on SotW must not discard the desired NPRDS capability.
    onSubscriptionConnectedForTest();
    setPolicyConfig(true);
    EXPECT_TRUE(subscriptionUseDeltaXdsForTest());
    EXPECT_EQ(CiliumTestPeer::subscriptionTypeUrl(*policy_map_), NetworkPolicyResourceTypeUrl);
    EXPECT_THAT(created_modes, testing::ElementsAre(true, false, true));
    EXPECT_EQ(state->start_calls_, 3);
  }
}

TEST_F(CiliumNetworkPolicyTest, TransportChangeWhileDisconnectedRecreatesImmediately) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  startManagedSubscriptionForTest();
  ASSERT_FALSE(subscriptionConnectedForTest());

  setPolicyConfig(true);

  EXPECT_TRUE(configuredUseDeltaXds());
  EXPECT_TRUE(subscriptionUseDeltaXdsForTest());
  EXPECT_FALSE(subscriptionConnectedForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(false, true));
  EXPECT_EQ(state->start_calls_, 2);
  EXPECT_TRUE(state->start_resources_.back().empty());
}

TEST_F(CiliumNetworkPolicyDeltaTest,
       TransportChangeFromDisconnectedDeltaToSotwRecreatesImmediately) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  startManagedSubscriptionForTest();
  ASSERT_FALSE(subscriptionConnectedForTest());
  ASSERT_TRUE(subscriptionUseDeltaXdsForTest());

  setPolicyConfig(false);

  EXPECT_FALSE(configuredUseDeltaXds());
  EXPECT_FALSE(subscriptionUseDeltaXdsForTest());
  EXPECT_FALSE(subscriptionConnectedForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(true, false));
  EXPECT_EQ(state->start_calls_, 2);
  EXPECT_TRUE(state->start_resources_.back().empty());
}

TEST_F(CiliumNetworkPolicyDeltaTest, DowngradeFromConnectedDeltaRecreatesDisconnectedRetryToSotw) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();
  ASSERT_TRUE(subscriptionConnectedForTest());
  ASSERT_TRUE(subscriptionUseDeltaXdsForTest());

  // Agent restart/downgrade drops the established delta transport. While the desired mode is still
  // delta we recreate immediately and begin retrying delta.
  onSubscriptionTransportCloseForTest();

  ASSERT_FALSE(subscriptionConnectedForTest());
  ASSERT_TRUE(subscriptionUseDeltaXdsForTest());
  ASSERT_EQ(state->start_calls_, 2);
  EXPECT_THAT(created_modes, testing::ElementsAre(true, true));
  EXPECT_TRUE(state->start_resources_.back().empty());

  // When listener metadata later reveals the downgraded agent no longer supports delta, flip to
  // SotW immediately rather than letting the disconnected delta retry loop forever.
  setPolicyConfig(false);

  EXPECT_FALSE(configuredUseDeltaXds());
  EXPECT_FALSE(subscriptionConnectedForTest());
  EXPECT_FALSE(subscriptionUseDeltaXdsForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(true, true, false));
  EXPECT_EQ(state->start_calls_, 3);
  EXPECT_TRUE(state->start_resources_.back().empty());
}

TEST_F(CiliumNetworkPolicyTest, TransportCloseWithoutConfigChangeRecreatesInCurrentMode) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();

  onSubscriptionTransportCloseForTest();

  EXPECT_FALSE(subscriptionConnectedForTest());
  EXPECT_FALSE(subscriptionUseDeltaXdsForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(false, false));
  EXPECT_EQ(state->start_calls_, 2);
  EXPECT_TRUE(state->start_resources_.back().empty());
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaPoliciesUseDeltaSdsForGenericSecrets) {
  EXPECT_CALL(secret_manager_,
              findOrCreateGenericSecretProvider(_, "nonexisting-sds-secret", _, _, _))
      .WillOnce(Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,
                          const std::string& config_name,
                          Server::Configuration::ServerFactoryContext& server_context,
                          OptRef<Init::Manager> init_manager, bool /* warm */) {
        EXPECT_TRUE(sds_config_source.has_api_config_source());
        EXPECT_EQ(envoy::config::core::v3::ApiConfigSource::DELTA_GRPC,
                  sds_config_source.api_config_source().api_type());
        auto secret_provider = Secret::GenericSecretSdsApi::create(
            server_context, sds_config_source, config_name, []() {}, false);
        init_manager->add(*secret_provider->initTarget());
        return secret_provider;
      }));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-43" ]
          http_rules:
            http_rules:
            - headers:
              - name: ':path'
                exact_match: '/allowed'
              header_matches:
              - name: 'bearer-token'
                value_sds_secret: 'nonexisting-sds-secret'
                mismatch_action: REPLACE_ON_MISMATCH
- name: "endpoint-for-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "42"
)EOF"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, SotwDowngrade) {
  auto state = std::make_shared<FakeSubscriptionState>();
  std::vector<bool> created_modes;
  setSubscriptionFactoryForTest(
      [state, &created_modes](bool use_delta_xds) -> std::unique_ptr<Envoy::Config::Subscription> {
        created_modes.push_back(use_delta_xds);
        return std::make_unique<FakeSubscription>(state);
      });

  using ApiType = envoy::config::core::v3::ApiConfigSource::ApiType;
  auto expect_tls_sds_mode = [this](ApiType api_type) {
    EXPECT_CALL(secret_manager_, findOrCreateTlsCertificateProvider(_, "secret1", _, _, _))
        .WillOnce(Invoke([api_type](const envoy::config::core::v3::ConfigSource& sds_config_source,
                                    const std::string& config_name,
                                    Server::Configuration::ServerFactoryContext& server_context,
                                    OptRef<Init::Manager> init_manager, bool /*warm*/) {
          EXPECT_TRUE(sds_config_source.has_api_config_source());
          EXPECT_EQ(api_type, sds_config_source.api_config_source().api_type());
          auto secret_provider = Secret::TlsCertificateSdsApi::create(
              server_context, sds_config_source, config_name, []() {}, false);
          if (init_manager.has_value()) {
            init_manager->add(*secret_provider->initTarget());
          }
          return secret_provider;
        }))
        .RetiresOnSaturation();
    EXPECT_CALL(secret_manager_,
                findOrCreateCertificateValidationContextProvider(_, "cacerts", _, _))
        .WillOnce(Invoke([api_type](const envoy::config::core::v3::ConfigSource& sds_config_source,
                                    const std::string& config_name,
                                    Server::Configuration::ServerFactoryContext& server_context,
                                    Init::Manager& init_manager) {
          EXPECT_TRUE(sds_config_source.has_api_config_source());
          EXPECT_EQ(api_type, sds_config_source.api_config_source().api_type());
          auto secret_provider = Secret::CertificateValidationContextSdsApi::create(
              server_context, sds_config_source, config_name, []() {}, false);
          init_manager.add(*secret_provider->initTarget());
          return secret_provider;
        }))
        .RetiresOnSaturation();
  };

  startManagedSubscriptionForTest();
  onSubscriptionConnectedForTest();
  ASSERT_TRUE(subscriptionConnectedForTest());
  ASSERT_TRUE(subscriptionUseDeltaXdsForTest());

  expect_tls_sds_mode(envoy::config::core::v3::ApiConfigSource::DELTA_GRPC);
  std::string version;
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "42"
- name: "42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      egress_per_port_policies:
      - port: 80
        rules:
        - server_names: [ "example.com" ]
          downstream_tls_context:
            tls_sds_secret: "secret1"
          upstream_tls_context:
            validation_context_sds_secret: "cacerts"
)EOF"));

  // Simulate xDS server restart and downgrade to SotW mode
  onSubscriptionTransportCloseForTest();

  ASSERT_FALSE(subscriptionConnectedForTest());
  ASSERT_TRUE(subscriptionUseDeltaXdsForTest());

  setPolicyConfig(false);

  ASSERT_FALSE(subscriptionConnectedForTest());
  ASSERT_FALSE(subscriptionUseDeltaXdsForTest());
  EXPECT_THAT(created_modes, testing::ElementsAre(true, true, false));

  onSubscriptionConnectedForTest();
  ASSERT_TRUE(subscriptionConnectedForTest());
  ASSERT_FALSE(subscriptionUseDeltaXdsForTest());

  // Same NetworkPolicy, but it must be updated for the secret watcher to also use SotW
  expect_tls_sds_mode(envoy::config::core::v3::ApiConfigSource::GRPC);
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - server_names: [ "example.com" ]
      downstream_tls_context:
        tls_sds_secret: "secret1"
      upstream_tls_context:
        validation_context_sds_secret: "cacerts"
)EOF"));
  EXPECT_EQ(version, "1");
}

TEST_F(CiliumNetworkPolicyTest, EmptyPolicyUpdate) {
  EXPECT_TRUE(subscriptionCallbacks().onConfigUpdate({}, "1").ok());
  EXPECT_FALSE(validate("10.1.2.3", "")); // Policy not found
}

TEST_F(CiliumNetworkPolicyTest, SimplePolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(validate("10.1.2.3", "")); // Policy not found
}

TEST_F(CiliumNetworkPolicyTest, RejectsWhitespaceInSotwWrappedResourceName) {
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/envoy.service.discovery.v3.Resource
  name: "policy 42"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicy
    endpoint_ips:
    - "10.1.2.3"
    endpoint_id: 42
)EOF"),
                            EnvoyException,
                            "NetworkPolicy resource name 'policy 42' must not contain whitespace");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaIncrementalPolicyUpdate) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 81));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 8080
        rules:
        - selectors: [ "selector-2" ]
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 8080));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaSameStreamKeepsUntouchedResources) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.2.3.4"
      epid: 43
      policy: "policy-43"
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 81
        rules:
        - selectors: [ "selector-2" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.2.3.4", 44, 81));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "selector-3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 45 ]
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 8080
        rules:
        - selectors: [ "selector-3" ]
- name: "endpoint-for-policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 8080));
  EXPECT_TRUE(ingressAllowed("10.2.3.4", 44, 81));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRemovesPolicyByResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.2.3.4"
      epid: 43
      policy: "policy-43"
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 81
        rules:
        - selectors: [ "selector-2" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      - "f00d::1"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("f00d::1"));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("f00d::1", 43, 80));

  EXPECT_TRUE(policy_map_->exists("10.2.3.4"));
  EXPECT_TRUE(ingressAllowed("10.2.3.4", 44, 81));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "endpoint-for-policy-42"
- "policy-42"
)EOF"));

  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  EXPECT_FALSE(policy_map_->exists("f00d::1"));
  EXPECT_FALSE(validate("10.1.2.3", ""));
  EXPECT_FALSE(validate("f00d::1", ""));

  EXPECT_TRUE(policy_map_->exists("10.2.3.4"));
  EXPECT_TRUE(ingressAllowed("10.2.3.4", 44, 81));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaEndpointUpdateMovesPolicyMapKeysAndMetadata) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3", "f00d::1" ]
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  const auto old_policy_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
  const auto old_policy = policy_map_->getPolicyInstance("10.1.2.3", false);
  ASSERT_NE(nullptr, old_policy_owner);
  EXPECT_EQ(42, old_policy.getEndpointID());
  ASSERT_NE(nullptr, old_policy.getEndpointIPs().ipv4_);
  ASSERT_NE(nullptr, old_policy.getEndpointIPs().ipv6_);
  EXPECT_EQ("10.1.2.3", old_policy.getEndpointIPs().ipv4_->ip()->addressAsString());
  EXPECT_EQ("f00d::1", old_policy.getEndpointIPs().ipv6_->ip()->addressAsString());
  EXPECT_EQ(old_policy_owner.get(), CiliumTestPeer::policyShared(*policy_map_, "f00d::1").get());

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.4", "f00d::2" ]
      epid: 84
      policy: "policy-a"
)EOF"));

  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  EXPECT_FALSE(policy_map_->exists("f00d::1"));
  const auto new_policy_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.4");
  const auto new_policy = policy_map_->getPolicyInstance("10.1.2.4", false);
  ASSERT_NE(nullptr, new_policy_owner);
  EXPECT_NE(old_policy_owner.get(), new_policy_owner.get());
  EXPECT_EQ(84, new_policy.getEndpointID());
  ASSERT_NE(nullptr, new_policy.getEndpointIPs().ipv4_);
  ASSERT_NE(nullptr, new_policy.getEndpointIPs().ipv6_);
  EXPECT_EQ("10.1.2.4", new_policy.getEndpointIPs().ipv4_->ip()->addressAsString());
  EXPECT_EQ("f00d::2", new_policy.getEndpointIPs().ipv6_->ip()->addressAsString());
  EXPECT_EQ(new_policy_owner.get(), CiliumTestPeer::policyShared(*policy_map_, "f00d::2").get());
}

TEST_F(CiliumNetworkPolicyDeltaTest, EndpointsSharePolicyWithIndependentIngressNamedPorts) {
  for (bool delta : {false, true}) {
    SCOPED_TRACE(delta ? "delta" : "sotw");
    resetStreamForTest();
    auto endpoint = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
endpoint:
  epid: 42
  ips: [10.1.2.3, "f00d::1"]
  named_ports:
  - {name: http, port: 8080}
  - {name: http, port: 8080}
  policy: shared-policy
)EOF");
    const auto second_endpoint = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
endpoint:
  epid: 43
  ips: [10.1.2.4]
  named_ports: [{name: http, port: 9090}]
  policy: shared-policy
)EOF");
    const auto selector =
        TestUtility::parseYaml<cilium::NetworkPolicyResource>("selector: {identities: [43]}");
    const auto other_selector =
        TestUtility::parseYaml<cilium::NetworkPolicyResource>("selector: {identities: [44]}");
    auto policy = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
policy:
  ingress_per_port_policies:
  - port_name: http
    rules:
    - selectors: [source]
      http_rules:
        http_rules:
        - headers:
          - {name: ":path", exact_match: /allowed}
  egress_per_port_policies:
  - port_name: http
)EOF");
    std::vector<std::pair<std::string, cilium::NetworkPolicyResource>> resources{
        {"endpoint-42", endpoint},
        {"endpoint-43", second_endpoint},
        {"shared-policy", policy},
        {"source", selector},
        {"other-source", other_selector}};
    applyResourceUpdate(resources, {}, delta);

    const auto retained_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
    const auto retained = policy_map_->getPolicyInstance("10.1.2.3", false);
    ASSERT_NE(retained_owner, nullptr);
    EXPECT_EQ(retained.getEndpointID(), 42);
    EXPECT_EQ(policy_map_->getPolicyInstance("10.1.2.4", false).getEndpointID(), 43);
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("f00d::1", 43, 8080, {{":path", "/allowed"}}));
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/denied"}}));
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9090, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("10.1.2.4", 43, 9090, {{":path", "/allowed"}}));
    EXPECT_FALSE(ingressAllowed("10.1.2.4", 43, 8080, {{":path", "/allowed"}}));
    EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 8181, NamedPorts{{8181, "http"}}));
    EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080, NamedPorts{}));

    endpoint.mutable_endpoint()->mutable_named_ports(0)->set_port(8081);
    endpoint.mutable_endpoint()->mutable_named_ports()->RemoveLast();
    resources[0].second = endpoint;
    applyResourceUpdate(
        delta ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{{"endpoint-42",
                                                                                    endpoint}}
              : resources,
        {}, delta);
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
    Http::TestRequestHeaderMapImpl headers{{":path", "/allowed"}};
    AccessLog::Entry log_entry;
    EXPECT_FALSE(policy_map_->getPolicyInstance("10.1.2.3", false)
                     .findIngressPortPolicy(8080)
                     .allowed(proxy_id_, 43, headers, log_entry));
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8081, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("f00d::1", 43, 8081, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("10.1.2.4", 43, 9090, {{":path", "/allowed"}}));
    EXPECT_TRUE(retained.findIngressPortPolicy(8080).allowed(proxy_id_, 43, ""));
    EXPECT_FALSE(retained.findIngressPortPolicy(8081).allowed(proxy_id_, 43, ""));

    // Rebinding a changed shared policy preserves each endpoint's own port mappings.
    policy.mutable_policy()->mutable_ingress_per_port_policies(0)->mutable_rules(0)->set_selectors(
        0, "other-source");
    resources[2].second = policy;
    applyResourceUpdate(
        delta ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{{"shared-policy",
                                                                                    policy}}
              : resources,
        {}, delta);
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 8081, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("10.1.2.4", 44, 9090, {{":path", "/allowed"}}));

    endpoint.mutable_endpoint()->clear_named_ports();
    resources[0].second = endpoint;
    applyResourceUpdate(
        delta ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{{"endpoint-42",
                                                                                    endpoint}}
              : resources,
        {}, delta);
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 8081, {{":path", "/allowed"}}));
    EXPECT_TRUE(ingressAllowed("10.1.2.4", 44, 9090, {{":path", "/allowed"}}));
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaEndpointUpdateRetargetsNamedPolicyAtomically) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "endpoint-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-a" ]
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-b" ]
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "policy-b"
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "3"
resources:
- name: "endpoint-42"
  version: "3"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "missing-policy"
)EOF"),
      EnvoyException,
      testing::HasSubstr("NetworkPolicyResource endpoint references missing policy resource "
                         "'missing-policy'"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsRemovingReferencedPolicy) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  const auto old_policy_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
  ASSERT_NE(nullptr, old_policy_owner);
  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "policy-a"
resources:
- name: remote
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    peer: {identity: 43, ips: [10.2.3.4]}
)EOF"),
      EnvoyException,
      testing::HasSubstr(
          "policy-a: policy is still referenced by endpoint resource 'endpoint-42'"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  EXPECT_EQ(old_policy_owner.get(), CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3").get());
  EXPECT_EQ(policy_map_
                ->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow("10.2.3.4")->ip())
                .value()
                .identity_,
            43);
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaSelectorOnlyUpdateTakesEffectImmediately) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  const struct {
    const char* identities;
    bool allow43;
    bool allow44;
  } cases[] = {{"44", false, true}, {"", false, false}, {"0", true, true}, {"43", true, false}};
  for (const auto& test_case : cases) {
    SCOPED_TRACE(test_case.identities);
    EXPECT_NO_THROW(deltaUpdateFromYaml(fmt::format(R"EOF(system_version_info: "2"
resources:
- name: "selector-1"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ {} ]
)EOF",
                                                    test_case.identities)));
    EXPECT_EQ(static_cast<bool>(ingressAllowed("10.1.2.3", 43, 80)), test_case.allow43);
    EXPECT_EQ(static_cast<bool>(ingressAllowed("10.1.2.3", 44, 80)), test_case.allow44);
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, RejectsInvalidResourceFeatures) {
  const struct {
    const char* yaml;
    const char* error;
  } cases[] = {
      {"endpoint: {epid: 42, ips: [10.1.2.3], policy: missing-policy}",
       "NetworkPolicyResource endpoint references missing policy resource 'missing-policy'"},
      {"peer: {identity: 0, ips: [10.1.2.3]}",
       "NetworkPolicyResource peer identity must be non-zero"},
  };
  for (const auto& test_case : cases) {
    SCOPED_TRACE(test_case.yaml);
    Config::DecodedResourcesWrapper resources;
    resources.pushBack(std::make_unique<Config::DecodedResourceImpl>(
        std::make_unique<cilium::NetworkPolicyResource>(
            TestUtility::parseYaml<cilium::NetworkPolicyResource>(test_case.yaml)),
        "unsupported", std::vector<std::string>{}, "1"));
    for (bool sotw : {false, true}) {
      const auto status = sotw ? subscriptionCallbacks().onConfigUpdate(resources.refvec_, "1")
                               : subscriptionCallbacks().onConfigUpdate(resources.refvec_, {}, "1");
      EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
      EXPECT_EQ(status.message(),
                fmt::format("Error adding/updating network policy resource(s) unsupported: {}",
                            test_case.error));
    }
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaPolicyUpdateRejectsMissingSelectorResource) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-for-policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-2" ]
)EOF"),
      EnvoyException,
      testing::HasSubstr(
          "Error adding/updating network policy resource(s) policy-42: NetworkPolicyResource rule "
          "references missing selector resource 'selector-2'"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaSelectorReAddRebindsOnlyResentPolicy) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: endpoint-for-policy-42
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: policy-42}
)EOF"));

  const auto old_policy = policyShared("10.1.2.3");
  ASSERT_NE(nullptr, old_policy);

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "selector-1"
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "3"
resources:
- name: "selector-1"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_EQ(old_policy.get(), policyShared("10.1.2.3").get());

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "4"
resources:
- name: "endpoint-for-policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_NE(old_policy.get(), policyShared("10.1.2.3").get());
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRemovedAndReaddedSelectorNameInSameUpdateActsAsUpdate) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  const std::string update = R"EOF(system_version_info: "2"
removed_resources:
- "selector-1"
resources:
- name: "selector-1"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
)EOF";
  for (int repeat : {0, 1}) {
    SCOPED_TRACE(repeat);
    EXPECT_NO_THROW(deltaUpdateFromYaml(update));

    EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectedSelectorUpdateKeepsPublishedBehavior) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "10.1.2.3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.3'.*incoming selector resource '10\.1\.2\.3'.*existing endpoint IP alias '10\.1\.2\.3' owned by endpoint resource 'endpoint-for-policy-42'.*epid 42.*10\.1\.2\.3.*policy 'policy-42')");

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, SdsInitializationFailureRetainsPolicyAndPublishesSelector) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: "policy"}
)EOF"));
  Init::TargetImpl failing_target("failing SDS", [this]() {
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
    EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
    EXPECT_FALSE(policy_map_->exists("10.1.2.4"));
    throw EnvoyException("SDS start failed");
  });
  EXPECT_CALL(secret_manager_, findOrCreateGenericSecretProvider(_, "failing-secret", _, _, _))
      .WillOnce(Invoke([&](const envoy::config::core::v3::ConfigSource& source,
                           const std::string& name,
                           Server::Configuration::ServerFactoryContext& context,
                           OptRef<Init::Manager> manager, bool) {
        manager->add(failing_target);
        return createSdsSecretProvider<Secret::GenericSecretSdsApi>(source, name, context, manager);
      }));
  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
- name: policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [selector]
          http_rules:
            http_rules:
            - header_matches: [{name: x-secret, value_sds_secret: failing-secret}]
- name: "endpoint-for-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: "policy"}
- name: sibling-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-sibling-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "sibling-policy"}
)EOF"),
      EnvoyException,
      testing::HasSubstr(
          "Error adding/updating network policy resource(s) policy: SDS start failed"));
  EXPECT_TRUE(ingressAllowed("10.1.2.4", 44, 80));
  ASSERT_EQ(CiliumTestPeer::policyStats(*policy_map_).updates_rejected_.value(), 1);
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "3"
resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
)EOF"));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaPassUsesCurrentSelectorMembership) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43, 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - precedence: 1000
          pass_precedence: 501
          selectors: [ "selector-1" ]
        - precedence: 900
          deny: true
        - precedence: 500
          selectors: [ "selector-2" ]
          http_rules:
            http_rules:
            - headers:
              - name: ':path'
                exact_match: '/allowed'
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaWildcardPortPassIsMergedToExactPortRules) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43, 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 0
        rules:
        - precedence: 1000
          pass_precedence: 501
          selectors: [ "selector-1" ]
      - port: 80
        rules:
        - precedence: 900
          deny: true
        - precedence: 500
          selectors: [ "selector-2" ]
          http_rules:
            http_rules:
            - headers:
              - name: ':path'
                exact_match: '/allowed'
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaSamePrecedenceDenyWinsOverPass) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - precedence: 1000
          pass_precedence: 501
          selectors: [ "selector-1" ]
        - precedence: 1000
          deny: true
          selectors: [ "selector-1" ]
        - precedence: 500
          selectors: [ "selector-1" ]
          http_rules:
            http_rules:
            - headers:
              - name: ':path'
                exact_match: '/allowed'
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaSelectorOnlyUpdateChangesPassBehaviorImmediately) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43, 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - precedence: 1000
          pass_precedence: 501
          selectors: [ "selector-1" ]
        - precedence: 900
          deny: true
        - precedence: 500
          selectors: [ "selector-2" ]
          http_rules:
            http_rules:
            - headers:
              - name: ':path'
                exact_match: '/allowed'
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "selector-1"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
)EOF"));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
}

TEST_F(CiliumNetworkPolicyTest, LegacyNpdsRejectsNamedPorts) {
  const auto baseline = TestUtility::parseYaml<cilium::NetworkPolicy>(R"EOF(
endpoint_id: 42
endpoint_ips: [10.1.2.3]
ingress_per_port_policies:
- port: 80
  rules:
  - remote_policies: [43]
egress_per_port_policies:
- port: 80
  rules:
  - remote_policies: [43]
)EOF");
  const struct {
    const char* name;
    bool ingress;
    bool udp;
  } cases[] = {
      {"ingress TCP", true, false},
      {"egress TCP", false, false},
      {"ingress UDP", true, true},
      {"egress UDP", false, true},
  };
  NetworkPolicyDecoder decoder;
  for (bool delta : {false, true}) {
    SCOPED_TRACE(delta ? "delta" : "sotw");
    const auto update = [&](const cilium::NetworkPolicy& policy) {
      envoy::service::discovery::v3::Resource resource;
      resource.set_name("42");
      resource.set_version("1");
      std::ignore = resource.mutable_resource()->PackFrom(policy);
      Config::DecodedResourcesWrapper decoded;
      decoded.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
      if (delta) {
        EXPECT_TRUE(subscriptionCallbacks().onConfigUpdate(decoded.refvec_, {}, "1").ok());
      } else {
        THROW_IF_NOT_OK(subscriptionCallbacks().onConfigUpdate(decoded.refvec_, "1"));
      }
    };
    EXPECT_NO_THROW(update(baseline));
    for (const auto& test_case : cases) {
      SCOPED_TRACE(test_case.name);
      auto invalid = baseline;
      auto* rule = test_case.ingress ? invalid.mutable_ingress_per_port_policies(0)
                                     : invalid.mutable_egress_per_port_policies(0);
      rule->set_port(0);
      rule->set_port_name("http");
      if (test_case.udp) {
        rule->set_protocol(envoy::config::core::v3::SocketAddress::UDP);
      }
      EXPECT_THROW_WITH_MESSAGE(update(invalid), EnvoyException,
                                "Legacy NPDS port_name 'http' must be resolved by the agent");
      EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
      EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80));
      EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
      EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 80));
    }
  }
}

TEST_F(CiliumNetworkPolicyTest, SotwRejectsSelectorsInRules) {
  EXPECT_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - selectors: [ "selector-1" ]
)EOF"),
               EnvoyException);
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsArbitrarySelectorResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "7"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44, 45 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "7" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsEmbeddedRemotePoliciesInRules) {
  EXPECT_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - remote_policies: [ 43 ]
)EOF"),
               EnvoyException);
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsArbitraryPolicyResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "42"
- name: "42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsAddedResourceNamesWithWhitespace) {
  EXPECT_THAT_THROWS_MESSAGE(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector 1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
)EOF"),
                             EnvoyException,
                             testing::HasSubstr("Error adding/updating network policy resource(s) "
                                                "selector 1: NetworkPolicyResource resource "
                                                "name 'selector 1' must not contain whitespace"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsRemovedResourceNamesWithWhitespace) {
  ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: retained-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: retained-endpoint
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: retained-policy}
)EOF",
                                  false)
                  .ok());
  const auto generation =
      CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value();
  resetStreamForTest();
  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "1"
removed_resources:
- "selector 1"
)EOF"),
      EnvoyException,
      testing::HasSubstr("Error adding/updating network policy resource(s) selector 1: "
                         "NetworkPolicyResource removed "
                         "resource name 'selector 1' must not contain whitespace"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  EXPECT_EQ(CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value(),
            generation);
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsDuplicatePolicyResourceNamesInSameUpdate) {
  EXPECT_THROW_WITH_REGEX(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "shared-name"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "shared-name"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
                          EnvoyException, R"(shared-name: duplicate resource name)");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsPolicyResourceNamesThatDoNotMatchEndpointId) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-43"
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsEndpointIpCollisionsInSameUpdate) {
  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 43
      policy: "policy-b"
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.3'.*incoming endpoint resource 'endpoint-for-policy-b'.*existing endpoint IP alias '10\.1\.2\.3' owned by endpoint resource 'endpoint-for-policy-a'.*epid 42.*10\.1\.2\.3.*policy 'policy-a')");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsResourceNameEndpointIpCollisionsInSameUpdate) {
  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "10.1.2.4"
- name: "10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "policy-b"
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.4'.*incoming endpoint resource 'endpoint-for-policy-b'.*existing policy resource '10\.1\.2\.4')");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsDuplicateSelectorResourceNamesInSameUpdate) {
  EXPECT_THROW_WITH_REGEX(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "shared-selector"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44, 45 ]
- name: "shared-selector"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 46, 47 ]
)EOF"),
                          EnvoyException, R"(shared-selector: duplicate resource name)");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsArbitraryPolicyResourceNamesWithHyphens) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "policy-qualified-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-qualified-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-qualified-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRemovesPoliciesByArbitraryResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "42"
- name: "42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-qualified-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "policy-qualified-43"
- name: "policy-qualified-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.4"));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "endpoint-for-42"
- "42"
)EOF"));

  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.4"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsEndpointIpCollisionsWithExistingPolicies) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-for-policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 43
      policy: "policy-b"
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.3'.*incoming endpoint resource 'endpoint-for-policy-b'.*existing endpoint IP alias '10\.1\.2\.3' owned by endpoint resource 'endpoint-for-policy-a'.*epid 42.*10\.1\.2\.3.*policy 'policy-a')");
}

TEST_F(CiliumNetworkPolicyDeltaTest,
       DeltaRejectsPolicyResourceNameCollidingWithExistingEndpointIp) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-for-10.1.2.3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "10.1.2.3"
- name: "10.1.2.3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.3'.*incoming policy resource '10\.1\.2\.3'.*existing endpoint IP alias '10\.1\.2\.3' owned by endpoint resource 'endpoint-for-policy-a'.*epid 42.*10\.1\.2\.3.*policy 'policy-a')");
}

TEST_F(CiliumNetworkPolicyDeltaTest,
       DeltaRejectsEndpointIpCollidingWithExistingPolicyResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "10.1.2.4"
- name: "10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "endpoint-for-policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "policy-b"
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.4'.*incoming endpoint resource 'endpoint-for-policy-b'.*existing policy resource '10\.1\.2\.4')");
}

TEST_F(CiliumNetworkPolicyDeltaTest,
       DeltaRejectsSelectorResourceNameCollidingWithExistingPolicyResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-shared-name"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "shared-name"
- name: "shared-name"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "shared-name"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key 'shared-name'.*incoming selector resource 'shared-name'.*existing policy resource 'shared-name')");
}

TEST_F(CiliumNetworkPolicyDeltaTest,
       DeltaRejectsSelectorResourceNameCollidingWithExistingEndpointIp) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THROW_WITH_REGEX(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "10.1.2.3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
)EOF"),
      EnvoyException,
      R"(Error adding/updating network policy resource\(s\).*duplicate resource key '10\.1\.2\.3'.*incoming selector resource '10\.1\.2\.3'.*existing endpoint IP alias '10\.1\.2\.3' owned by endpoint resource 'endpoint-for-policy-a'.*epid 42.*10\.1\.2\.3.*policy 'policy-a')");
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsRemovingEndpointIpAlias) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-a"
- name: "policy-a"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "10.1.2.3"
)EOF"),
      EnvoyException,
      testing::HasSubstr("Error adding/updating network policy resource(s) 10.1.2.3: "
                         "NetworkPolicyResource removed "
                         "resource '10.1.2.3' is a policy endpoint IP alias, not a "
                         "resource name"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAllowsEndpointIpReusingRemovedPolicyResourceName) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "10.1.2.4"
- name: "10.1.2.4"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
removed_resources:
- "endpoint-for-10.1.2.4"
- "10.1.2.4"
resources:
- name: "endpoint-for-policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "policy-b"
- name: "policy-b"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.4"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsPolicyResourceNamesWithNumericSuffixes) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-042"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-042"
- name: "policy-042"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-0"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.4"
      epid: 43
      policy: "policy-0"
- name: "policy-0"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"));

  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map_->exists("10.1.2.4"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsZeroEndpointIdRegardlessOfResourceName) {
  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-0"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 0
      policy: "policy-0"
- name: "policy-0"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
)EOF"),
      EnvoyException,
      testing::HasSubstr("endpoint-for-policy-0: NetworkPolicyResource epid must be non-zero"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsInconsistentPassPrecedence) {
  EXPECT_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - precedence: 1000
          pass_precedence: 100
          selectors: [ "selector-1" ]
        - precedence: 900
          pass_precedence: 200
          selectors: [ "selector-2" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"),
               EnvoyException);
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaNewStreamReplacesStateWithFullSnapshot) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.2.3.4"
      epid: 43
      policy: "policy-43"
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 81
        rules:
        - selectors: [ "selector-2" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.2.3.4", 44, 81));

  resetStreamForTest();

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "selector-3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 45 ]
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 8080
        rules:
        - selectors: [ "selector-3" ]
- name: "endpoint-for-policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 8080));
  EXPECT_FALSE(policy_map_->exists("10.2.3.4"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaNewStreamClearsStaleResourceNamesFromResourceMap) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "selector-1"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "selector-2"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 80
        rules:
        - selectors: [ "selector-1" ]
- name: "endpoint-for-policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.2.3.4"
      epid: 43
      policy: "policy-43"
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 81
        rules:
        - selectors: [ "selector-2" ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  resetStreamForTest();

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "2"
resources:
- name: "selector-3"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 45 ]
- name: "policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 8080
        rules:
        - selectors: [ "selector-3" ]
- name: "endpoint-for-policy-42"
  version: "2"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
)EOF"));

  EXPECT_FALSE(policy_map_->exists("10.2.3.4"));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "3"
resources:
- name: "policy-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 46 ]
)EOF"));

  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "4"
resources:
- name: "endpoint-for-policy-42"
  version: "3"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips:
      - "10.1.2.3"
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "3"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 9090
        rules:
        - selectors: [ "policy-43" ]
)EOF"));

  EXPECT_TRUE(ingressAllowed("10.1.2.3", 46, 9090));
}

TEST_F(CiliumNetworkPolicyDeltaTest, FirstResponseKeepsStateUntilAResourceIsAccepted) {
  const struct {
    const char* name;
    const char* resources;
    bool reset;
    bool selector;
    bool policy;
    bool error;
  } cases[] = {
      {"selector only", R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
)EOF",
       true, true, false, false},
      {"peer only", R"EOF(resources:
- name: remote
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    peer: {identity: 44, ips: [10.2.3.4]}
)EOF",
       true, false, false, false},
      {"peer accepted, endpoint rejected", R"EOF(resources:
- name: remote
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    peer: {identity: 44, ips: [10.2.3.4]}
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 0, ips: [10.1.2.4], policy: missing-policy}
)EOF",
       true, false, false, true},
      {"policy and endpoint", R"EOF(resources:
- name: new-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-new-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "new-policy"}
)EOF",
       true, false, true, false},
      {"selector accepted, policy rejected", R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [missing-selector]}]}]
- name: "endpoint-for-bad-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 0, ips: [10.1.2.4], policy: "bad-policy"}
)EOF",
       true, true, false, true},
      {"policy cannot use old namespace", R"EOF(resources:
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-bad-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "bad-policy"}
)EOF",
       false, false, false, true},
      {"all resources rejected", R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44, 44]}
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-bad-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "bad-policy"}
)EOF",
       false, false, false, true},
      {"valid policy and invalid sibling", R"EOF(resources:
- name: new-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-new-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "new-policy"}
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [missing-selector]}]}]
- name: "endpoint-for-bad-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "bad-policy"}
)EOF",
       true, false, true, true},
  };
  for (bool sotw : {false, true}) {
    for (const auto& test_case : cases) {
      SCOPED_TRACE(testing::Message() << test_case.name << " sotw=" << sotw);
      resetStreamForTest();
      ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: old-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-old-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: "old-policy"}
)EOF",
                                      true)
                      .ok());
      const auto generation =
          CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value();
      resetStreamForTest();
      const auto status = nprdsUpdateFromYaml(test_case.resources, sotw);
      EXPECT_EQ(status.ok(), !test_case.error) << status;
      if (test_case.error) {
        EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
        EXPECT_THAT(status.message(), testing::HasSubstr("bad-policy: "));
      }
      EXPECT_EQ(policy_map_->exists("10.1.2.3"), !test_case.reset);
      EXPECT_EQ(policy_map_->exists("10.1.2.4"), test_case.policy);
      EXPECT_EQ(CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value(),
                generation + test_case.reset);
      if (!test_case.reset) {
        EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
        EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
      }
      if (test_case.selector) {
        ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: followup-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-followup-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 44, ips: [10.1.2.5], policy: "followup-policy"}
)EOF",
                                        false)
                        .ok());
        EXPECT_TRUE(ingressAllowed("10.1.2.5", 44, 80));
        EXPECT_FALSE(ingressAllowed("10.1.2.5", 43, 80));
        EXPECT_EQ(CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value(),
                  generation + 1);
      } else if (!test_case.reset) {
        ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
)EOF",
                                        false)
                        .ok());
        EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
        EXPECT_EQ(CiliumTestPeer::policyStats(*policy_map_).policy_stream_generation_.value(),
                  generation + 1);
      }
    }
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, PartialUpdatesRetainFailedReplacementsAndApplyRemovals) {
  for (bool sotw : {false, true}) {
    for (bool bad_selector : {false, true}) {
      SCOPED_TRACE(bad_selector);
      SCOPED_TRACE(sotw);
      resetStreamForTest();
      ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: retained-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-retained-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3, "fd00::3"], policy: "retained-policy"}
- name: removed-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-removed-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "removed-policy"}
)EOF",
                                      false)
                      .ok());
      std::string response = R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
- name: retained-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [missing-selector]}]}]
- name: "endpoint-for-retained-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3, "fd00::3"], policy: "retained-policy"}
- name: new-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-new-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 44, ips: [10.1.2.5], policy: "new-policy"}
- name: invalid-selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [45, 45]}
)EOF" + std::string(sotw ? ""
                         : "removed_resources: [endpoint-for-removed-policy, removed-policy]\n");
      if (bad_selector) {
        response.replace(response.find("identities: [44]"), std::string("identities: [44]").size(),
                         "identities: [44, 44]");
      }
      const auto status = nprdsUpdateFromYaml(response, sotw);
      EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
      EXPECT_THAT(status.message(),
                  testing::StartsWith("Error adding/updating network policy resource(s) "));
      EXPECT_THAT(status.message(), testing::HasSubstr("retained-policy: "));
      EXPECT_THAT(status.message(), testing::HasSubstr("invalid-selector: "));
      EXPECT_TRUE(policy_map_->exists("fd00::3"));
      EXPECT_FALSE(policy_map_->exists("10.1.2.4"));
      EXPECT_FALSE(policy_map_->exists("10.1.2.6"));
      EXPECT_TRUE(ingressAllowed("10.1.2.3", bad_selector ? 43 : 44, 80));
      EXPECT_FALSE(ingressAllowed("10.1.2.3", bad_selector ? 44 : 43, 80));
      EXPECT_TRUE(ingressAllowed("10.1.2.5", bad_selector ? 43 : 44, 80));
      // Retrying a NACKed response keeps its successful subset usable.
      EXPECT_FALSE(nprdsUpdateFromYaml(response, sotw).ok());
      EXPECT_TRUE(ingressAllowed("10.1.2.5", bad_selector ? 43 : 44, 80));
    }
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, PolicyInstancesKeepOnePublishedPolicyAndSelectorVersion) {
  class DeferredThreads : public ThreadLocal::MockInstance {
  public:
    void runOnAllWorkerThreads(std::function<void()> worker,
                               std::function<void()> completion) const override {
      worker();
      completions_.push_back(std::move(completion));
    }
    void quiesce() {
      while (!completions_.empty()) {
        auto callbacks = std::move(completions_);
        completions_.clear();
        for (auto& callback : callbacks) {
          callback();
        }
      }
    }
    ~DeferredThreads() override { quiesce(); }
    mutable std::vector<std::function<void()>> completions_;
  } threads;
  auto& context = factory_context_.server_factory_context_;
  auto& original_threads = context.threadLocal();
  ON_CALL(context, threadLocal()).WillByDefault(testing::ReturnRef(threads));

  const struct {
    bool new_stream;
    bool replace_policy;
  } cases[] = {{false, false}, {false, true}, {true, true}};
  for (const auto& test_case : cases) {
    SCOPED_TRACE(testing::Message() << "new_stream=" << test_case.new_stream
                                    << " replace_policy=" << test_case.replace_policy);
    resetStreamForTest();
    ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: "policy"}
)EOF",
                                    false)
                    .ok());
    threads.quiesce();
    const auto old_policy = policy_map_->getPolicyInstance("10.1.2.3", false);
    if (test_case.new_stream) {
      resetStreamForTest();
    }
    std::string update = R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
- name: bad-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [missing-selector]}]}]
- name: "endpoint-for-bad-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 0, ips: [10.1.2.4], policy: "bad-policy"}
)EOF";
    if (test_case.replace_policy) {
      update += R"EOF(- name: policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 8080, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.3], policy: "policy"}
)EOF";
    }
    EXPECT_EQ(nprdsUpdateFromYaml(update, false).code(), absl::StatusCode::kInvalidArgument);
    const auto new_policy = policy_map_->getPolicyInstance("10.1.2.3", false);
    EXPECT_EQ(old_policy.getEndpointID(), 42);
    EXPECT_TRUE(old_policy.findIngressPortPolicy(80).allowed(proxy_id_, 43, ""));
    EXPECT_FALSE(old_policy.findIngressPortPolicy(80).allowed(proxy_id_, 44, ""));
    EXPECT_EQ(new_policy.getEndpointID(), test_case.replace_policy ? 43 : 42);
    const uint16_t port = test_case.replace_policy ? 8080 : 80;
    EXPECT_TRUE(new_policy.findIngressPortPolicy(port).allowed(proxy_id_, 44, ""));
    EXPECT_FALSE(new_policy.findIngressPortPolicy(port).allowed(proxy_id_, 43, ""));
    EXPECT_EQ(new_policy.findIngressPortPolicy(80).allowed(proxy_id_, 44, ""),
              !test_case.replace_policy);
    threads.quiesce();
  }
  ON_CALL(context, threadLocal()).WillByDefault(testing::ReturnRef(original_threads));
}

TEST_F(CiliumNetworkPolicyDeltaTest, MalformedPayloadDoesNotDiscardValidResources) {
  for (bool sotw : {false, true}) {
    SCOPED_TRACE(sotw);
    NetworkPolicyResourceDecoder decoder;
    Config::DecodedResourcesWrapper decoded;
    auto append = [&](const std::string& name, const Protobuf::Any& payload) {
      envoy::service::discovery::v3::Resource resource;
      resource.set_name(name);
      resource.mutable_resource()->CopyFrom(payload);
      if (sotw) {
        Protobuf::Any wrapper;
        ASSERT_TRUE(wrapper.PackFrom(resource));
        auto result = Config::DecodedResourceImpl::fromResource(decoder, wrapper, "1");
        ASSERT_TRUE(result.ok()) << result.status();
        decoded.pushBack(std::move(result.value()));
      } else {
        decoded.pushBack(Config::DecodedResourceImpl::fromResource(decoder, resource));
      }
    };

    {
      Protobuf::Any payload;
      payload.set_type_url("type.googleapis.com/cilium.NetworkPolicyResource");
      payload.set_value(std::string(1, static_cast<char>(0xff)));
      ASSERT_NO_THROW(append("malformed", payload));

      cilium::NetworkPolicyResource invalid_selector;
      invalid_selector.mutable_selector()->add_identities(43);
      invalid_selector.mutable_selector()->add_identities(43);
      ASSERT_TRUE(payload.PackFrom(invalid_selector));
      append("invalid-selector", payload);

      cilium::NetworkPolicyResource valid_policy;
      valid_policy.mutable_policy();
      ASSERT_TRUE(payload.PackFrom(valid_policy));
      append("valid-policy", payload);
      cilium::NetworkPolicyResource endpoint;
      endpoint.mutable_endpoint()->set_epid(42);
      endpoint.mutable_endpoint()->add_ips("10.1.2.3");
      endpoint.mutable_endpoint()->set_policy("valid-policy");
      ASSERT_TRUE(payload.PackFrom(endpoint));
      append("valid-endpoint", payload);
    }

    // Both transports must own the decoded messages after the input wrappers have been destroyed.
    resetStreamForTest();
    const auto status = sotw ? subscriptionCallbacks().onConfigUpdate(decoded.refvec_, "1")
                             : subscriptionCallbacks().onConfigUpdate(decoded.refvec_, {}, "1");
    EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
    EXPECT_THAT(status.message(), testing::HasSubstr("malformed: "));
    EXPECT_THAT(status.message(), testing::HasSubstr("invalid-selector: "));
    EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, FailedReplacementsRetainAliasesAndRejectDependentClaims) {
  for (bool sotw : {false, true}) {
    SCOPED_TRACE(sotw);
    resetStreamForTest();
    ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: policy-a
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy-a"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.3], policy: "policy-a"}
- name: policy-b
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy-b"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.4], policy: "policy-b"}
)EOF",
                                    false)
                    .ok());
    const auto status = nprdsUpdateFromYaml(R"EOF(resources:
- name: selector
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [43]}
- name: 10.1.2.3
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector: {identities: [44]}
- name: policy-a
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [selector]}]}]
- name: "endpoint-for-policy-a"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.4], policy: "policy-a"}
- name: policy-b
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [missing]}]}]
- name: "endpoint-for-policy-b"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 0, ips: [10.1.2.7], policy: "policy-b"}
- name: policy-c
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies: [{port: 80, rules: [{selectors: [10.1.2.3]}]}]
- name: "endpoint-for-policy-c"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 44, ips: [10.1.2.5], policy: "policy-c"}
- name: independent-policy
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-independent-policy"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 45, ips: [10.1.2.6], policy: "independent-policy"}
)EOF",
                                            sotw);
    EXPECT_EQ(status.code(), absl::StatusCode::kInvalidArgument);
    for (const char* name :
         {"endpoint-for-policy-a", "policy-b", "endpoint-for-policy-b", "10.1.2.3", "policy-c"}) {
      EXPECT_THAT(status.message(), testing::HasSubstr(fmt::format("{}: ", name)));
    }
    EXPECT_EQ(policy_map_->getPolicyInstance("10.1.2.3", false).getEndpointID(), 42);
    EXPECT_EQ(policy_map_->getPolicyInstance("10.1.2.4", false).getEndpointID(), 43);
    EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
    EXPECT_TRUE(ingressAllowed("10.1.2.4", 43, 80));
    EXPECT_FALSE(policy_map_->exists("10.1.2.5"));
    EXPECT_TRUE(policy_map_->exists("10.1.2.6"));
    EXPECT_FALSE(policy_map_->exists("10.1.2.7"));

    // Successful replacements can still exchange aliases within the same atomic update.
    ASSERT_TRUE(nprdsUpdateFromYaml(R"EOF(resources:
- name: policy-a
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-a"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 42, ips: [10.1.2.4], policy: "policy-a"}
- name: policy-b
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy: {}
- name: "endpoint-for-policy-b"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint: {epid: 43, ips: [10.1.2.3], policy: "policy-b"}
)EOF",
                                    sotw)
                    .ok());
    EXPECT_EQ(policy_map_->getPolicyInstance("10.1.2.3", false).getEndpointID(), 43);
    EXPECT_EQ(policy_map_->getPolicyInstance("10.1.2.4", false).getEndpointID(), 42);
  }
}

TEST_F(CiliumNetworkPolicyTest, OverlappingPortRange) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 23
    rules:
    - remote_policies: [ 42 ]
    - remote_policies: [ 45 ]
  - port: 80
    rules:
    - remote_policies: [ 44 ]
  - port: 92
    rules:
    - deny: true
  - port: 40
    end_port: 99
    rules:
    - remote_policies: [ 43 ]
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [23-23]:
    - rules:
      - remotes: [45]
      - remotes: [42]
    [40-79]:
    - rules:
      - remotes: [43]
    [80-80]:
    - rules:
      - remotes: [44]
      - remotes: [43]
    [81-91]:
    - rules:
      - remotes: [43]
    [92-92]:
    - rules:
      - remotes: []
        deny: true
      - remotes: [43]
    [93-99]:
    - rules:
      - remotes: [43]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 42 is allowed on port 23
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 42, 23));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 23));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 23));

  // port 92 is denied from everyone
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 42, 92));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 92));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 92));

  // Ingress from 43 is allowed on all ports of the range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 39));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 40));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 99));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 100));

  // 44 is only allowed to port 80
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 39));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 40));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 81));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 99));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 100));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));

  // Same with policies added in reverse order
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 40
    end_port: 99
    rules:
    - remote_policies: [ 43 ]
  - port: 92
    rules:
    - deny: true
  - port: 80
    rules:
    - remote_policies: [ 44 ]
  - port: 23
    rules:
    - remote_policies: [ 42 ]
    - remote_policies: [ 45 ]
)EOF"));

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 42 is allowed on port 23
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 42, 23));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 23));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 23));

  // port 92 is denied from everyone
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 42, 92));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 92));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 92));

  // Ingress from 43 is allowed on all ports of the range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 39));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 40));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 99));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 100));

  // 44 is only allowed to port 80
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 39));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 40));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 81));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 99));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 100));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));
}

TEST_F(CiliumNetworkPolicyTest, OverlappingPortRanges) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 44 ]
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-4039]:
    - rules:
      - remotes: [43]
    [4040-8080]:
    - rules:
      - remotes: [43]
      - remotes: [44]
    [8081-9999]:
    - rules:
      - remotes: [44]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is allowed to ports 80-8080 only:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9998));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));

  // Same with policies added in reverse order
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 44 ]
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
)EOF"));

  // remotes are in insertion order
  expected = R"EOF(ingress:
  rules:
    [80-4039]:
    - rules:
      - remotes: [43]
    [4040-8080]:
    - rules:
      - remotes: [44]
      - remotes: [43]
    [8081-9999]:
    - rules:
      - remotes: [44]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is allowed to ports 80-8080 only:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9998));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));

  // Validate no overflow when splitting port ranges with existing port range containing U16 max.
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 32768
    end_port: 65534
    rules:
    - remote_policies: [ 43 ]
  - port: 32768
    end_port: 65535
    rules:
    - remote_policies: [ 44 ]
  - port: 1024
    end_port: 65535
    rules:
    - remote_policies: [ 45 ]
)EOF"));

  expected = R"EOF(ingress:
  rules:
    [1024-32767]:
    - rules:
      - remotes: [45]
    [32768-65534]:
    - rules:
      - remotes: [43]
      - remotes: [44]
      - remotes: [45]
    [65535-65535]:
    - rules:
      - remotes: [44]
      - remotes: [45]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 40000));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 65535));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 40000));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 65535));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 40000));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 65535));

  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 40000));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 65535));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 45, 8080));
}

TEST_F(CiliumNetworkPolicyTest, DuplicatePorts) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
  - port: 80
    rules:
    - remote_policies: [ 43 ]
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
      - remotes: [43]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is allowed on port 80 only:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 8080));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, DuplicatePortRange) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
  - port: 80
    rules:
    - remote_policies: [ 43 ]
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
      - remotes: [43]
    [81-8080]:
    - rules:
      - remotes: [43]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress is allowed:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, InvalidPortRange) {
  EXPECT_THROW_WITH_MESSAGE(
      updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 60
    rules:
    - remote_policies: [ 43 ]
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 43 ]
)EOF"),
      EnvoyException,
      "PortNetworkPolicy: Invalid port range, end port is less than start port 80-60");

  // No ingress is allowed:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, InvalidWildcardPortRange) {
  EXPECT_THROW_WITH_MESSAGE(
      updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    end_port: 80
    rules:
    - remote_policies: [ 43 ]
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 43 ]
)EOF"),
      EnvoyException,
      "PortNetworkPolicy: Invalid port range including the wildcard zero port 0-80");

  // No ingress is allowed:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
}

// Zero end port is treated as no range
TEST_F(CiliumNetworkPolicyTest, ZeroPortRange) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 0
    rules:
    - remote_policies: [ 43 ]
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 43 ]
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
    [4040-9999]:
    - rules:
      - remotes: [43]
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80));
  // Allowed port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path is ignored:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80));
}

TEST_F(CiliumNetworkPolicyTest, HttpPolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

  // 1st update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  // 2nd update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {}
              regex: '.*public$'
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Wrong path:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));

  // 3rd update with Ingress deny rules
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "3"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    end_port: 10000
    rules:
    - deny: true
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {}
              regex: '.*public$'
)EOF"));
  EXPECT_EQ(version, "3");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        deny: true
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
    [81-10000]:
    - rules:
      - remotes: []
        deny: true
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Denied remote ID, port, & path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Denied remote ID & wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Wrong path:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));

  // 4th update with matching proxy_id in policy
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "4"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    end_port: 10000
    rules:
    - proxy_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {}
              regex: '.*public$'
)EOF"));
  EXPECT_EQ(version, "4");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        proxy_id: 42
    [81-10000]:
    - rules:
      - remotes: []
        proxy_id: 42
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Matching proxy ID:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Matching proxy ID:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Matching proxy ID:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79, {{":path", "/allowed"}}));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10001, {{":path", "/notallowed"}}));

  // 5th update with non-matching proxy_id in policy
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "5"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    end_port: 10000
    rules:
    - proxy_id: 99
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            safe_regex_match:
              google_re2: {}
              regex: '.*public$'
)EOF"));
  EXPECT_EQ(version, "5");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        proxy_id: 99
    [81-10000]:
    - rules:
      - remotes: []
        proxy_id: 99
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Non-matching proxy ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Non-matching proxy ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Non-matching proxy ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79, {{":path", "/allowed"}}));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10001, {{":path", "/notallowed"}}));
}

TEST_F(CiliumNetworkPolicyTest, Precedence) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

  // pass_precedence must be lower than precedence
  EXPECT_THROW_WITH_MESSAGE(
      updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 2000
      remote_policies: [ 43 ]
)EOF"),
      EnvoyException,
      "PortNetworkPolicyRule: pass_precedence 2000 must be lower than precedence 1000");

  // deny and pass_precedence are mutually exclusive
  EXPECT_THROW_WITH_REGEX(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - deny: true
      precedence: 1000
      pass_precedence: 100
      remote_policies: [ 43 ]
)EOF"),
                          EnvoyException,
                          "Unable to parse JSON as proto.*INVALID_ARGUMENT:.*oneof");

  // pass rules on the same tier must use a consistent pass_precedence.
  // "pass_precedence" defines the last (lowest) precedence on the "tier".
  // any pass rules with precedence higher than the previous pass_precedence
  // must have the same pass_precedence.
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 100
      remote_policies: [ 43 ]
    - precedence: 900
      pass_precedence: 200
      remote_policies: [ 44 ]
)EOF"),
                            EnvoyException,
                            "PortNetworkPolicy: Inconsistent pass precedence 200 != 100");

  //
  // 1st update: Default allow rule combining with an HTTP allow rule
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected1 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        name: "default allow rule"
      - remotes: []
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected1));

  // All remotes allowed on port 80
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/also-allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 2nd update: Default allow rule combining with a pass rule.
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 81
    rules:
    - precedence: 10
      pass_precedence: 1
  - port: 80
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected2 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        precedence: 10
        tier_last_precedence: 1
      - remotes: []
        name: "default allow rule"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected2));

  // All remotes allowed on port 80
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/also-allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 3rd update: Default allow rule combining with a pass rule on wildcard port.
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "3"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 10
      pass_precedence: 1
  - port: 80
)EOF"));
  EXPECT_EQ(version, "3");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected3 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        precedence: 10
        tier_last_precedence: 1
      - remotes: []
        name: "default allow rule"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected3));

  // All remotes allowed on port 80
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/also-allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 4th update: higher precedence deny
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "4"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      deny: true
    - precedence: 100
      remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "4");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected4 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        deny: true
        precedence: 1000
      - remotes: [43]
        precedence: 100
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected4));

  // Denied remote ID, port, & path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 5th update: higher precedence deny on wildcard port
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "5"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 1000
      deny: true
  - port: 80
    rules:
    - precedence: 100
      remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "5");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected5 = R"EOF(ingress:
  rules:
    [0-0]:
    - rules:
      - remotes: []
        deny: true
        precedence: 1000
    [80-80]:
    - rules:
      - remotes: []
        deny: true
        precedence: 1000
      - remotes: [43]
        precedence: 100
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected5));

  // Denied remote ID, port, & path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 6th update: pass for '43'
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "6"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 43 ]
    - precedence: 900
      deny: true
    - precedence: 500
      remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "6");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected6 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: [43]
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected6));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 7th update: pass with partial overlap
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "7"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 43 ]
    - precedence: 900
      deny: true
    - precedence: 500
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "7");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected7 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: [43,44]
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected7));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Denied remote ID, port, & path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 8th update: wildcard pass
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "8"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 501
    - precedence: 900
      deny: true
    - precedence: 500
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "8");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected8 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: [43,44]
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected8));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 9th update: split wildcard lower-precedence rule due to pass
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "9"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 43 ]
    - precedence: 900
      deny: true
    - precedence: 500
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "9");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected9 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: []
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected9));

  // Remote 43 matches the pass rule and skips the intermediate deny.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Other remotes are still denied by the deny rule.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allowed"}}));

  //
  // 10th update: wildcard-port pass inherited by specific port rules
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "10"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 43 ]
  - port: 80
    rules:
    - precedence: 900
      deny: true
    - precedence: 500
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "10");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected10 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: [43,44]
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected10));

  // Pass from wildcard port lets remote 43 skip the deny on port 80.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Remote 44 is denied because only 43 matches the pass rule.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  // Unspecified remotes remain denied.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  //
  // 11th update: wildcard-port and specific-port pass rules at equal precedence
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "11"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 44 ]
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 501
      remote_policies: [ 43 ]
    - precedence: 900
      deny: true
    - precedence: 500
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "11");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected11 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: [44]
        precedence: 1000
        tier_last_precedence: 501
      - remotes: []
        deny: true
        precedence: 900
      - remotes: [43,44]
        precedence: 500
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected11));

  // Both IDs are passed to the lower allow despite the intermediate deny.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allowed"}}));

  //
  // 12th update: pass tier keeps native rules in runtime order
  //
  // With runtime pass handling the pass rule remains present, the higher-precedence
  // deny for remote 44 stays in place, and the lower allow rules are evaluated in
  // their native form instead of being rewritten during preprocessing.
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "12"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 701
      remote_policies: [ 45 ]
    - precedence: 900
      deny: true
      remote_policies: [ 44 ]
    - precedence: 800
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allow-a'
    - precedence: 800
      remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allow-b'
    - precedence: 700
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allow-c'
)EOF"));
  EXPECT_EQ(version, "12");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected12 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [45]
        precedence: 1000
        tier_last_precedence: 701
      - remotes: [44]
        deny: true
        precedence: 900
      - remotes: [43]
        precedence: 800
        http_rules:
        - headers:
          - name: ":path"
            value: "/allow-b"
      - remotes: [43,44]
        precedence: 800
        http_rules:
        - headers:
          - name: ":path"
            value: "/allow-a"
      - remotes: []
        precedence: 700
        http_rules:
        - headers:
          - name: ":path"
            value: "/allow-c"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected12));

  // Remote 43 is not passed, but both same-precedence allow rules remain effective.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allow-a"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allow-b"}}));
  // Remote 44 is denied by the higher-precedence deny before either allow rule is reached.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-a"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-b"}}));
  // Pass remote 45 does not match /allow-a because only the lower wildcard allow matches it.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allow-a"}}));
  // Pass remote 45 reaches the lower wildcard allow at precedence 700.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allow-c"}}));
  // Non-pass remotes not already denied at higher precedence still match the
  // original wildcard rule at precedence 700.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allow-c"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-c"}}));

  //
  // 13th update: inherited wildcard and local pass rules both remain
  //
  // Runtime pass handling keeps both pass rules visible in precedence order. The
  // specific-port pass is checked before the inherited wildcard-port pass for the
  // same remote, but neither rule is rewritten away.
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "13"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 900
      pass_precedence: 701
      remote_policies: [ 43 ]
  - port: 80
    rules:
    - precedence: 1000
      pass_precedence: 701
      remote_policies: [ 43 ]
    - precedence: 800
      deny: true
    - precedence: 700
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/shadowed-inherited-pass'
)EOF"));
  EXPECT_EQ(version, "13");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected13 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1000
        tier_last_precedence: 701
      - remotes: [43]
        precedence: 900
        tier_last_precedence: 701
      - remotes: []
        deny: true
        precedence: 800
      - remotes: [43,44]
        precedence: 700
        http_rules:
        - headers:
          - name: ":path"
            value: "/shadowed-inherited-pass"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected13));

  // Remote 43 hits the specific-port pass before the intermediate deny.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/shadowed-inherited-pass"}}));
  // Remote 44 remains denied by the intermediate deny.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/shadowed-inherited-pass"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/shadowed-inherited-pass"}}));

  //
  // 14th update: multiple inherited pass tiers are handled at runtime
  //
  // The wildcard-port pass rules remain visible in the exact-port rule list. Remote 41
  // still reaches the intermediate deny, while remote 42 matches the lower wildcard pass
  // and skips that deny to the allow at precedence 600.
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "14"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 1300
      pass_precedence: 1000
      remote_policies: [ 41 ]
    - precedence: 900
      pass_precedence: 700
      remote_policies: [ 42 ]
  - port: 80
    rules:
    - precedence: 750
      deny: true
    - precedence: 600
      remote_policies: [ 41, 42, 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/multi-tier'
)EOF"));
  EXPECT_EQ(version, "14");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected14 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [41]
        precedence: 1300
        tier_last_precedence: 1000
      - remotes: [42]
        precedence: 900
        tier_last_precedence: 700
      - remotes: []
        deny: true
        precedence: 750
      - remotes: [41,42,43]
        precedence: 600
        http_rules:
        - headers:
          - name: ":path"
            value: "/multi-tier"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected14));

  // Remote 41 does not match the lower pass tier, so it still hits the deny at 850.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 41, 80, {{":path", "/multi-tier"}}));
  // Remote 42 matches the lower pass tier and skips the deny to the allow at precedence 600.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 42, 80, {{":path", "/multi-tier"}}));
  // Remote 43 does not match either pass tier and is denied.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/multi-tier"}}));

  //
  // 15th update: inconsistent pass precedence via inherited wildcard + local pass
  //
  // Wildcard current-tier pass (900/700) is inherited for port 80 at local
  // pass precedence 850. A local pass with pass_precedence 600 on the same tier
  // must fail as inconsistent.
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "15"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 900
      pass_precedence: 700
      remote_policies: [ 50 ]
  - port: 80
    rules:
    - precedence: 850
      pass_precedence: 600
      remote_policies: [ 51 ]
    - precedence: 500
      remote_policies: [ 50, 51 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/inconsistent-inherited-pass'
)EOF"),
                            EnvoyException,
                            "PortNetworkPolicy: Inconsistent pass precedence 600 != 700");

  // Failed update must leave policy unchanged from version 14.
  EXPECT_TRUE(validate("10.1.2.3", expected14));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 41, 80, {{":path", "/multi-tier"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 42, 80, {{":path", "/multi-tier"}}));

  //
  // 16th update: inherited wildcard pass skips remaining rules on that tier at runtime
  //
  // The pass rule and the skipped-tier rules remain present in the rendered policy, but a
  // matching remote jumps past the 1200/1100 rules and reaches the lower-tier allow at 600.
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "16"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 2000
      pass_precedence: 700
  - port: 80
    rules:
    - precedence: 1200
      deny: true
      remote_policies: [ 43 ]
    - precedence: 1100
      remote_policies: [ 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/should-skip'
    - precedence: 600
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/promoted-after-skip'
)EOF"));
  EXPECT_EQ(version, "16");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected16 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        precedence: 2000
        tier_last_precedence: 700
      - remotes: [43]
        deny: true
        precedence: 1200
      - remotes: [44]
        precedence: 1100
        http_rules:
        - headers:
          - name: ":path"
            value: "/should-skip"
      - remotes: [43,44]
        precedence: 600
        http_rules:
        - headers:
          - name: ":path"
            value: "/promoted-after-skip"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected16));

  // Both remotes are allowed by the lower-tier rule reached after the wildcard pass.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/promoted-after-skip"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/promoted-after-skip"}}));
  // The 1100 rule remains present but is skipped by the inherited wildcard pass.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/should-skip"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/promoted-after-skip"}}));

  //
  // 17th update: overlapping lower rules remain visible under runtime pass handling
  //
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "17"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - precedence: 1000
      pass_precedence: 901
  - port: 80
    rules:
    - precedence: 900
      deny: true
      remote_policies: [ 43 ]
    - precedence: 800
      remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/should-skip'
    - precedence: 600
      remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/partially-skipped'
)EOF"));
  EXPECT_EQ(version, "17");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected17 = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: []
        precedence: 1000
        tier_last_precedence: 901
      - remotes: [43]
        deny: true
        precedence: 900
      - remotes: [43]
        precedence: 800
        http_rules:
        - headers:
          - name: ":path"
            value: "/should-skip"
      - remotes: [43,44]
        precedence: 600
        http_rules:
        - headers:
          - name: ":path"
            value: "/partially-skipped"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected17));

  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/partially-skipped"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/partially-skipped"}}));
  // Rule at 800 remains present, but the higher-precedence deny still wins for remote 43.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/should-skip"}}));
  // inapplicable identity
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/partially-skipped"}}));
}

TEST_F(CiliumNetworkPolicyTest, HttpPassEvaluatesL7Rules) {
  std::string version;

  // NetworkPolicy captured from cilium-dbg for the tiered policy reproducer.
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "fd00:10:244:1::5619"
  - "10.244.1.233"
  endpoint_id: "131"
  ingress_per_port_policies:
  - rules:
    - remote_policies:
      - 1
      precedence: 4294967041
    - deny: true
      precedence: 4294961919
  - rules:
    - remote_policies:
      - 1
      precedence: 4294956801
    - deny: true
      precedence: 4294956799
  - port: 8080
    rules:
    - pass_precedence: 4294959616
      remote_policies:
      - 23626
      precedence: 4294967040
      http_rules:
        http_rules:
        - headers:
          - name: ":method"
            string_match:
              safe_regex:
                regex: "GET"
  - port: 8080
    rules:
    - remote_policies:
      - 23626
      precedence: 4294959514
      http_rules:
        http_rules:
        - headers:
          - name: ":path"
            string_match:
              safe_regex:
                regex: "/"
  egress_per_port_policies:
  - {}
)EOF"));
  EXPECT_EQ(version, "1");

  EXPECT_TRUE(ingressAllowed("10.244.1.233", 23626, 8080, {{":method", "GET"}, {":path", "/"}}));
  EXPECT_FALSE(ingressAllowed("10.244.1.233", 23626, 8080, {{":method", "POST"}, {":path", "/"}}));
  EXPECT_FALSE(
      ingressAllowed("10.244.1.233", 23626, 8080, {{":method", "GET"}, {":path", "/public"}}));
  EXPECT_FALSE(ingressAllowed("10.244.1.233", 1234, 8080, {{":method", "GET"}, {":path", "/"}}));
}

TEST_F(CiliumNetworkPolicyTest, HttpOverlappingPortRanges) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

  // 1st update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':method'
            exact_match: 'GET'
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":method"
            value: "GET"
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & method OR path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "GET"}, {":path", "/also_allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  // 2nd update with overlapping port range and a single port
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 70
    end_port: 90
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':method'
            exact_match: 'GET'
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [70-79]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
    [80-80]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":method"
            value: "GET"
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
    [81-90]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & method OR path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 70, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 90, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "GET"}, {":path", "/also_allowed"}}));
  // wrong port for GET
  EXPECT_FALSE(
      ingressAllowed("10.1.2.3", 43, 70, {{":method", "GET"}, {":path", "/also_allowed"}}));
  EXPECT_FALSE(
      ingressAllowed("10.1.2.3", 43, 90, {{":method", "GET"}, {":path", "/also_allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  // 3rd update with overlapping port ranges
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 70
    end_port: 90
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':method'
            exact_match: 'GET'
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  expected = R"EOF(ingress:
  rules:
    [70-79]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
    [80-90]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":method"
            value: "GET"
    [91-8080]:
    - rules:
      - remotes: [43]
        http_rules:
        - headers:
          - name: ":method"
            value: "GET"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Allowed remote ID, port, & method OR path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 70, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 90, {{":method", "PUSH"}, {":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":method", "GET"}, {":path", "/also_allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 90, {{":method", "GET"}, {":path", "/also_allowed"}}));
  EXPECT_TRUE(
      ingressAllowed("10.1.2.3", 43, 8080, {{":method", "GET"}, {":path", "/also_allowed"}}));
  // wrong port for GET
  EXPECT_FALSE(
      ingressAllowed("10.1.2.3", 43, 70, {{":method", "GET"}, {":path", "/also_allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
}

TEST_F(CiliumNetworkPolicyTest, TcpPolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

  // 1st update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  // Allowed remote ID & port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path does not matter:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  // 2nd update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43, 44 ]
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  // Allowed remote ID & port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path does not matter
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID & port:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Path does not matter:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
}

TEST_F(CiliumNetworkPolicyTest, PortRanges) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));

  // 1st update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  // Allowed remote ID & port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  // Path does not matter
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
  // Port within the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  // Port at the end of the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80));

  // 2nd update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
  - port: 9000
    end_port: 9999
    rules:
    - remote_policies: [ 44 ]
  egress_per_port_policies:
  - port: 80
    end_port: 90
    rules:
    - remote_policies: [ 43, 44 ]
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID & port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80));
  // Path does not matter
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
  // Port within the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  // Port at the end of the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8081));

  // Allowed remote ID & port:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 9000));
  // Port within the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 9500));
  // Port at the end of the range:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 9999));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 8999));
  // Port out of range:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 10000));

  // Wrong remote IDs:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9000));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9500));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 9999));

  // Allowed remote ID & port:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80));
  // Path does not matter:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 80));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80));
  // Port within the range:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 85));
  // Port at the end of the range:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 90));
  // Port out of range:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 91));

  // 3rd update, ranges with HTTP
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
  - port: 9000
    end_port: 9999
    rules:
    - remote_policies: [ 44 ]
  egress_per_port_policies:
  - port: 80
    end_port: 90
    rules:
    - remote_policies: [ 43, 44 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
        - headers:
          - name: ':path'
            exact_match: '/allows'
        - headers:
          - name: ':path'
            exact_match: '/public'
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 80, {{":path", "/allows"}}));
  // Wrong remote ID:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Port within the range:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 85, {{":path", "/allows"}}));
  // Port at the end of the range:
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 90, {{":path", "/public"}}));
  // Port out of range:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 79, {{":path", "/allows"}}));
  // Port out of range:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 91, {{":path", "/public"}}));
}

TEST_F(CiliumNetworkPolicyTest, HttpPolicyUpdateToMissingSDS) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

  // 1st update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

  // 2nd update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - headers:
          - name: ':path'
            exact_match: '/allowed'
          header_matches:
          - name: 'bearer-token'
            value_sds_secret: 'nonexisting-sds-secret'
            mismatch_action: REPLACE_ON_MISMATCH
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));
  // Drop due to the missing SDS secret
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
}

TEST_F(CiliumNetworkPolicyTest, TlsContextsAreDeduplicatedWithinStream) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.3" ]
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 443
    rules:
    - remote_policies: [ 43 ]
      downstream_tls_context:
        tls_sds_secret: "shared-cert"
        validation_context_sds_secret: "shared-ca"
  egress_per_port_policies:
  - port: 443
    rules:
    - remote_policies: [ 43 ]
      upstream_tls_context:
        tls_sds_secret: "shared-cert"
        validation_context_sds_secret: "shared-ca"
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.4" ]
  endpoint_id: 44
  ingress_per_port_policies:
  - port: 443
    rules:
    - remote_policies: [ 43 ]
      downstream_tls_context:
        tls_sds_secret: "shared-cert"
        validation_context_sds_secret: "shared-ca"
  egress_per_port_policies:
  - port: 443
    rules:
    - remote_policies: [ 43 ]
      upstream_tls_context:
        tls_sds_secret: "shared-cert"
        validation_context_sds_secret: "shared-ca"
)EOF"));

  const auto& first = policy_map_->getPolicyInstance("10.1.2.3", false);
  const auto& second = policy_map_->getPolicyInstance("10.1.2.4", false);

  const auto* first_downstream = tlsContextConfig(first, true, 43, 443);
  const auto* second_downstream = tlsContextConfig(second, true, 43, 443);
  const auto* first_upstream = tlsContextConfig(first, false, 43, 443);
  const auto* second_upstream = tlsContextConfig(second, false, 43, 443);

  EXPECT_EQ(first_downstream, second_downstream);
  EXPECT_EQ(first_upstream, second_upstream);
  EXPECT_NE(first_downstream, first_upstream);
}

TEST_F(CiliumNetworkPolicyTest, SecretWatchersAreDeduplicatedWithinStream) {
  EXPECT_CALL(secret_manager_,
              findOrCreateGenericSecretProvider(_, "shared-header-secret", _, _, _));

  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.3" ]
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - header_matches:
          - name: "x-shared-secret"
            value: "first-header-value"
            value_sds_secret: "shared-header-secret"
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.4" ]
  endpoint_id: 44
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - header_matches:
          - name: "x-shared-secret"
            value: "second-header-value"
            value_sds_secret: "shared-header-secret"
)EOF"));

  // The missing shared SDS value leaves each HeaderMatch's own inline fallback in effect.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{"x-shared-secret", "first-header-value"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{"x-shared-secret", "second-header-value"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.4", 43, 80, {{"x-shared-secret", "second-header-value"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.4", 43, 80, {{"x-shared-secret", "first-header-value"}}));
}

TEST_F(CiliumNetworkPolicyTest, SecretWatcherCacheIsResetForNewStream) {
  EXPECT_CALL(secret_manager_, findOrCreateGenericSecretProvider(_, "header-secret", _, _, _))
      .Times(2);

  const auto policy_yaml = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.3" ]
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      http_rules:
        http_rules:
        - header_matches:
          - name: "x-secret"
            value: "header-value"
            value_sds_secret: "header-secret"
)EOF";

  EXPECT_NO_THROW(updateFromYaml(policy_yaml));
  auto old_policy_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
  ASSERT_NE(old_policy_owner, nullptr);
  const auto old_policy = policy_map_->getPolicyInstance("10.1.2.3", false);

  CiliumTestPeer::resetStream(*policy_map_);
  EXPECT_NO_THROW(updateFromYaml(policy_yaml));

  Http::TestRequestHeaderMapImpl old_headers{{"x-secret", "header-value"}};
  Cilium::AccessLog::Entry old_log_entry;
  EXPECT_TRUE(
      old_policy.findIngressPortPolicy(80).allowed(proxy_id_, 43, old_headers, old_log_entry));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{"x-secret", "header-value"}}));
}

TEST_F(CiliumNetworkPolicyTest, TlsContextCacheIsResetForNewStream) {
  const auto policy_yaml = R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips: [ "10.1.2.3" ]
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 443
    rules:
    - remote_policies: [ 43 ]
      downstream_tls_context:
        tls_sds_secret: "shared-cert"
)EOF";

  EXPECT_NO_THROW(updateFromYaml(policy_yaml));
  auto old_policy_owner = CiliumTestPeer::policyShared(*policy_map_, "10.1.2.3");
  ASSERT_NE(old_policy_owner, nullptr);
  const auto old_policy = policy_map_->getPolicyInstance("10.1.2.3", false);
  const auto* old_config = tlsContextConfig(old_policy, true, 43, 443);

  CiliumTestPeer::resetStream(*policy_map_);
  EXPECT_NO_THROW(updateFromYaml(policy_yaml));

  const auto& new_policy = policy_map_->getPolicyInstance("10.1.2.3", false);
  const auto* new_config = tlsContextConfig(new_policy, true, 43, 443);
  EXPECT_NE(old_config, new_config);

  // Resetting the cache must not invalidate contexts retained by the old policy map.
  EXPECT_EQ(old_config, tlsContextConfig(old_policy, true, 43, 443));
}

TEST_F(CiliumNetworkPolicyTest, TlsPolicyUpdate) {
  bool tls_socket_required;
  bool raw_socket_allowed;

  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  // SNI does not make a difference
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));

  // 1st update without TLS requirements
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
)EOF"));
  EXPECT_EQ(version, "1");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID & port:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // SNI does not matter:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 2nd update without TLS requirements, with lower precedence wildcard port deny
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - remote_policies: [ 43 ]
      deny: true
      precedence: 0
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      precedence: 1
)EOF"));
  EXPECT_EQ(version, "2");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  std::string expected2 = R"EOF(ingress:
  rules:
    [0-0]:
    - rules:
      - remotes: [43]
        deny: true
    [80-80]:
    - rules:
      - remotes: [43]
        precedence: 1
      - remotes: [43]
        deny: true
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected2));

  // Allowed remote ID & port:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // SNI does not matter:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 3rd update without TLS requirements, with same precedence wildcard port deny
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "3"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - remote_policies: [ 43 ]
      deny: true
      precedence: 0
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      precedence: 0
)EOF"));
  EXPECT_EQ(version, "3");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Denied remote ID & port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // SNI does not matter:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 4th update without TLS requirements, with higher precedence wildcard port deny
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "4"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 0
    rules:
    - remote_policies: [ 43 ]
      deny: true
      precedence: 1
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      precedence: 0
)EOF"));
  EXPECT_EQ(version, "4");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Denied remote ID & port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // SNI does not matter:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 5th Update: TLS SNI update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "5"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      server_names: [ "cilium.io", "example.com" ]
)EOF"));
  EXPECT_EQ(version, "5");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // Allowed remote ID, port, incorrect SNI:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "www.example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsIngressAllowed("10.1.2.3", 43, 80, "cilium.io", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_TRUE(raw_socket_allowed);
  // Missing SNI:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 6th update: TLS Interception update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "6"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      server_names: [ "cilium.io", "example.com" ]
      downstream_tls_context:
        tls_sds_secret: "secret1"
      upstream_tls_context:
        validation_context_sds_secret: "cacerts"
)EOF"));
  EXPECT_EQ(version, "6");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsEgressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, incorrect SNI:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "www.example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsEgressAllowed("10.1.2.3", 43, 80, "cilium.io", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Missing SNI:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(
      tlsEgressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No igress is allowed:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 7th update: TLS Termination update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "7"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      server_names: [ "cilium.io", "example.com" ]
      downstream_tls_context:
        tls_sds_secret: "secret1"
)EOF"));
  EXPECT_EQ(version, "7");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(tlsIngressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, incorrect SNI:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "www.example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsIngressAllowed("10.1.2.3", 43, 80, "cilium.io", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Missing SNI:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                 raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No egress is allowed:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // 8th update: TLS Origination update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "8"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
      upstream_tls_context:
        validation_context_sds_secret: "cacerts"
)EOF"));
  EXPECT_EQ(version, "8");
  EXPECT_TRUE(policy_map_->exists("10.1.2.3"));

  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsEgressAllowed("10.1.2.3", 43, 80, "example.com", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port,  SNI:
  EXPECT_TRUE(tlsEgressAllowed("10.1.2.3", 43, 80, "www.example.com", tls_socket_required,
                               raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Allowed remote ID, port, SNI:
  EXPECT_TRUE(
      tlsEgressAllowed("10.1.2.3", 43, 80, "cilium.io", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Empty SNI:
  EXPECT_TRUE(tlsEgressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_TRUE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong remote ID:
  EXPECT_FALSE(
      tlsEgressAllowed("10.1.2.3", 40, 80, "example.com", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
  // Wrong port:
  EXPECT_FALSE(tlsEgressAllowed("10.1.2.3", 43, 8080, "example.com", tls_socket_required,
                                raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);

  // No igress is allowed:
  EXPECT_FALSE(tlsIngressAllowed("10.1.2.3", 43, 80, "", tls_socket_required, raw_socket_allowed));
  EXPECT_FALSE(tls_socket_required);
  EXPECT_FALSE(raw_socket_allowed);
}

TEST_F(CiliumNetworkPolicyTest, EmptyRulesAllow) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies: [{}]
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [0-0]:
    - rules:
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is denied to ports 80-4039, but allowed on ports 4040-9999:
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8081));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9998));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9999));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));
}

TEST_F(CiliumNetworkPolicyTest, SNIPatternMatching) {
  Regex::GoogleReEngine engine;

  std::string exception_msg_regex = "SniPattern: Unsupported match pattern .*";
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "***"), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "example.***.com"), EnvoyException,
                          exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "example.c**"), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "example.com."), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "example..com"), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "^example.com$"), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, ".+example.com"), EnvoyException, exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "[a-zA-Z]*.example.com"), EnvoyException,
                          exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "example.[a-zA-Z0-9]+"), EnvoyException,
                          exception_msg_regex)
  EXPECT_THROW_WITH_REGEX(SniPattern(engine, "(foo|bar|baz).example.com"), EnvoyException,
                          exception_msg_regex)

  // Test empty pattern
  SniPattern empty(engine, "");
  EXPECT_FALSE(empty.matches("example.com"));
  EXPECT_FALSE(empty.matches("EXAMPLE.COM"));
  EXPECT_FALSE(empty.matches("www.example.com"));
  EXPECT_FALSE(empty.matches("notexample.com"));
  EXPECT_FALSE(empty.matches(""));

  // Test exact matches
  SniPattern exact(engine, "example.com");
  EXPECT_TRUE(exact.matches("example.com"));
  EXPECT_TRUE(exact.matches("EXaMpLE.COM"));
  EXPECT_FALSE(exact.matches("www.example.com"));
  EXPECT_FALSE(exact.matches("notexample.com"));
  EXPECT_FALSE(exact.matches(""));

  SniPattern exact_with_subdomain(engine, "foo.bar.example.com");
  EXPECT_TRUE(exact_with_subdomain.matches("foo.bar.example.com"));
  EXPECT_TRUE(exact_with_subdomain.matches("foo.BaR.example.COM"));
  EXPECT_FALSE(exact_with_subdomain.matches("bar.example.com"));
  EXPECT_FALSE(exact_with_subdomain.matches("foo.bar.example.org"));
  EXPECT_FALSE(exact_with_subdomain.matches(""));

  // Test full wildcard pattern.
  std::string full_wildcard_specifiers[] = {"*", "**"};
  for (const std::string& pattern : full_wildcard_specifiers) {
    SniPattern full_wildcard(engine, pattern);
    EXPECT_TRUE(full_wildcard.matches("localhost"));
    EXPECT_TRUE(full_wildcard.matches("example.com"));
    EXPECT_TRUE(full_wildcard.matches("foo.007.example.com"));
    EXPECT_TRUE(full_wildcard.matches("foo.bar.example.com"));
    EXPECT_TRUE(full_wildcard.matches("foo.BaR.example.COM"));
    EXPECT_TRUE(full_wildcard.matches("foo-bar.example.com"));
    EXPECT_FALSE(full_wildcard.matches("example.com."));
    EXPECT_FALSE(full_wildcard.matches("ex@mple.com"));
    EXPECT_FALSE(full_wildcard.matches(""));
  }

  // Test subdomain wildcard matches
  SniPattern subdomain_wildcard(engine, "*.example.com");
  EXPECT_TRUE(subdomain_wildcard.matches("foo.example.com"));
  EXPECT_TRUE(subdomain_wildcard.matches("bar-007.example.com"));
  EXPECT_TRUE(subdomain_wildcard.matches("FOO.EXaMpLE.COM"));
  EXPECT_FALSE(subdomain_wildcard.matches("example.com"));
  EXPECT_FALSE(subdomain_wildcard.matches("foo.bar.example.com"));
  EXPECT_FALSE(subdomain_wildcard.matches("fooexample.com"));
  EXPECT_FALSE(subdomain_wildcard.matches(""));

  // Test wildcard label in between the subdomains
  SniPattern wildcard_label(engine, "sub.*.com");
  EXPECT_TRUE(wildcard_label.matches("sub.foo.com"));
  EXPECT_TRUE(wildcard_label.matches("sub.bar.com"));
  EXPECT_TRUE(wildcard_label.matches("sub.foobar.COM"));
  EXPECT_FALSE(wildcard_label.matches("test.sub.example.com"));
  EXPECT_FALSE(wildcard_label.matches("sub.com"));
  EXPECT_FALSE(wildcard_label.matches("fooexample.com"));
  EXPECT_FALSE(wildcard_label.matches(""));

  // Test wildcard label in between name
  SniPattern mixed_wildcard_label(engine, "sub.example-*.com");
  EXPECT_TRUE(mixed_wildcard_label.matches("sub.example-foo.com"));
  EXPECT_TRUE(mixed_wildcard_label.matches("sub.exAmPle-007.com"));
  EXPECT_TRUE(mixed_wildcard_label.matches("sub.example-foo-bar.com"));
  EXPECT_FALSE(mixed_wildcard_label.matches("sub.example.com"));
  EXPECT_FALSE(mixed_wildcard_label.matches("sub.example-foo.bar.com"));

  // Multiple wildcard labels
  SniPattern multi_wildcard_labels(engine, "sub.*.*.example.com");
  EXPECT_TRUE(multi_wildcard_labels.matches("sub.foo.bar.example.com"));
  EXPECT_TRUE(multi_wildcard_labels.matches("sub.foo.007.example.com"));
  EXPECT_FALSE(multi_wildcard_labels.matches("sub.foo.example.com"));
  EXPECT_FALSE(multi_wildcard_labels.matches("sub.example.com"));
  EXPECT_FALSE(multi_wildcard_labels.matches(""));

  // Test double wildcard matches
  SniPattern double_wildcard(engine, "sub.**.example.com");
  EXPECT_TRUE(double_wildcard.matches("sub.foo.example.com"));
  EXPECT_TRUE(double_wildcard.matches("sub.foo.bar-007.ExAmPle.com"));
  EXPECT_FALSE(double_wildcard.matches("sub.foo.example.com.extra"));
  EXPECT_FALSE(double_wildcard.matches("sub.example.com"));
  EXPECT_FALSE(double_wildcard.matches("sub..example.com"));
  EXPECT_FALSE(double_wildcard.matches("007.sub.ExAmPlE.com"));
  EXPECT_FALSE(double_wildcard.matches("foo.sub.example.com"));
  EXPECT_FALSE(double_wildcard.matches(""));

  // Test subdomain double wildcard matches
  SniPattern subdomains_double_wildcard(engine, "**.sub.example.com");
  EXPECT_TRUE(subdomains_double_wildcard.matches("foo.sub.example.com"));
  EXPECT_TRUE(subdomains_double_wildcard.matches("bar-007.sub.example.com"));
  EXPECT_TRUE(subdomains_double_wildcard.matches("foo.bar.sub.example.com"));
  EXPECT_TRUE(subdomains_double_wildcard.matches("007.sub.ExAmPlE.com"));
  EXPECT_FALSE(subdomains_double_wildcard.matches("sub.example.com"));
  EXPECT_FALSE(subdomains_double_wildcard.matches("foo.example.com"));
  EXPECT_FALSE(subdomains_double_wildcard.matches(""));

  // Multiple wildcard labels with multilevel subdomain prefix wildcard.
  SniPattern all_wildcard_labels(engine, "**.sub.*.ex*e.com");
  EXPECT_TRUE(all_wildcard_labels.matches("foo.sub.bar.example.com"));
  EXPECT_TRUE(all_wildcard_labels.matches("test.foo.sub.bar.example.com"));
  EXPECT_TRUE(all_wildcard_labels.matches("test.foo.sub.bar.exe.com"));
  EXPECT_FALSE(all_wildcard_labels.matches("test.sub.foobar.com"));
  EXPECT_FALSE(all_wildcard_labels.matches("test.sub.example.com"));
  EXPECT_FALSE(all_wildcard_labels.matches("sub.test.example.com"));
  EXPECT_FALSE(all_wildcard_labels.matches(""));

  // Multiple wildcard labels with multilevel subdomain prefix wildcard.
  SniPattern multi_wildcard_label(engine, "sub.*exa*.com");
  EXPECT_TRUE(multi_wildcard_label.matches("sub.example.com"));
  EXPECT_TRUE(multi_wildcard_label.matches("sub.examples.com"));
  EXPECT_TRUE(multi_wildcard_label.matches("sub.exa.com"));
  EXPECT_FALSE(multi_wildcard_label.matches("sub.foobar.com"));
  EXPECT_FALSE(multi_wildcard_label.matches("test.sub.example.com"));
  EXPECT_FALSE(multi_wildcard_label.matches("sub.test.example.com"));
  EXPECT_FALSE(multi_wildcard_label.matches(""));
}

TEST_F(CiliumNetworkPolicyTest, OrderedRules) {
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
      precedence: 0
      deny: true
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 43 ]
      precedence: 1
)EOF"));

  std::string expected = R"EOF(ingress:
  rules:
    [80-4039]:
    - rules:
      - remotes: [43]
        deny: true
    [4040-8080]:
    - rules:
      - remotes: [43]
        precedence: 1
      - remotes: [43]
        deny: true
    [8081-9999]:
    - rules:
      - remotes: [43]
        precedence: 1
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is denied to ports 80-4039, but allowed on ports 4040-9999:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8081));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9998));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));

  // Same with policies added in reverse order
  EXPECT_NO_THROW(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 4040
    end_port: 9999
    rules:
    - remote_policies: [ 43 ]
      precedence: 1
  - port: 80
    end_port: 8080
    rules:
    - remote_policies: [ 43 ]
      precedence: 0
      deny: true
)EOF"));

  EXPECT_TRUE(validate("10.1.2.3", expected));

  // Ingress from 43 is denied to ports 80-4039, but allowed on ports 4040-9999:
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 79));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 81));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8081));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9998));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(egressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 44, 8080));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaAcceptsNamedPortPolicyBeforePeerMappings) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      named_ports: [{ name: http, port: 8080 }]
      policy: "policy-42"
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port_name: http
      - port_name: metrics
)EOF"));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyDeltaTest, PeerLookupsFollowAcceptedUpdates) {
  const struct {
    const char* name;
    bool delta;
    bool peers_first;
  } cases[] = {
      {"sotw peers first", false, true},
      {"sotw peers last", false, false},
      {"delta peers first", true, true},
      {"delta peers last", true, false},
  };
  for (const auto& test_case : cases) {
    SCOPED_TRACE(test_case.name);
    resetStreamForTest();
    auto peer = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
peer:
  identity: 43
  ips: [ "10.2.3.4", "f00d::43" ]
  named_ports:
  - { name: metrics, port: 9090 }
  - { name: http, port: 8080 }
  - { name: http, port: 8080 }
)EOF");
    const auto fallback = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
peer:
  identity: 44
  ips: [ "10.0.0.0/8", "f00d::/64" ]
)EOF");
    auto selector =
        TestUtility::parseYaml<cilium::NetworkPolicyResource>("selector: { identities: [43] }");
    const auto policy = TestUtility::parseYaml<cilium::NetworkPolicyResource>(R"EOF(
policy:
  egress_per_port_policies:
  - port_name: http
    rules:
    - selectors: [ selector ]
)EOF");
    const auto endpoint = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
        "endpoint: { epid: 42, ips: [10.1.2.3], policy: policy }");
    std::vector<std::pair<std::string, cilium::NetworkPolicyResource>> resources{
        {"remote", peer},
        {"fallback", fallback},
        {"selector", selector},
        {"policy", policy},
        {"endpoint", endpoint}};
    if (!test_case.peers_first) {
      std::rotate(resources.begin(), resources.begin() + 2, resources.end());
    }
    applyResourceUpdate(resources, {}, test_case.delta);
    const auto resolve = [this](const std::string& ip) {
      return policy_map_->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow(ip)->ip())
          .value();
    };

    const auto retained = resolve("10.2.3.4");
    EXPECT_EQ(retained.identity_, 43);
    EXPECT_THAT(retained.namedPorts(),
                testing::ElementsAre(NamedPort{8080, "http"}, NamedPort{9090, "metrics"}));
    EXPECT_EQ(resolve("f00d::43").identity_, 43);
    EXPECT_EQ(resolve("10.2.3.5").identity_, 44);
    EXPECT_EQ(resolve("f00d::44").identity_, 44);
    EXPECT_EQ(resolve("192.0.2.1").identity_, ID::UNKNOWN);
    auto port_policy = policy_map_->getPolicyInstance("10.1.2.3", false)
                           .findEgressPortPolicy(8080, retained.named_ports_);
    EXPECT_TRUE(port_policy.allowed(proxy_id_, retained.identity_, ""));

    peer.mutable_peer()->set_identity(45);
    peer.mutable_peer()->clear_ips();
    peer.mutable_peer()->add_ips("10.3.4.5");
    peer.mutable_peer()->add_ips("f00d::45");
    peer.mutable_peer()->clear_named_ports();
    auto* named_port = peer.mutable_peer()->add_named_ports();
    named_port->set_name("http");
    named_port->set_port(8081);
    for (auto& [name, config] : resources) {
      if (name == "remote") {
        config = peer;
      }
    }
    applyResourceUpdate(
        test_case.delta
            ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{{"remote", peer}}
            : resources,
        {}, test_case.delta);
    EXPECT_TRUE(policy_map_->getPolicyInstance("10.1.2.3", false)
                    .findEgressPortPolicy(8080, retained.named_ports_)
                    .allowed(proxy_id_, retained.identity_, ""));
    EXPECT_EQ(resolve("10.2.3.4").identity_, 44);
    EXPECT_EQ(resolve("f00d::43").identity_, 44);
    const auto updated = resolve("10.3.4.5");
    EXPECT_EQ(updated.identity_, 45);
    EXPECT_THAT(updated.namedPorts(), testing::ElementsAre(NamedPort{8081, "http"}));
    EXPECT_EQ(resolve("f00d::45").identity_, 45);
    EXPECT_FALSE(policy_map_->getPolicyInstance("10.1.2.3", false)
                     .findEgressPortPolicy(8081, updated.named_ports_)
                     .allowed(proxy_id_, updated.identity_, ""));

    selector.mutable_selector()->set_identities(0, 45);
    for (auto& [name, config] : resources) {
      if (name == "selector") {
        config = selector;
      }
    }
    applyResourceUpdate(
        test_case.delta
            ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{{"selector",
                                                                                  selector}}
            : resources,
        {}, test_case.delta);
    EXPECT_EQ(resolve("10.3.4.5").identity_, 45);
    EXPECT_TRUE(policy_map_->getPolicyInstance("10.1.2.3", false)
                    .findEgressPortPolicy(8081, updated.named_ports_)
                    .allowed(proxy_id_, updated.identity_, ""));

    std::erase_if(resources, [](const auto& resource) { return resource.first == "remote"; });
    applyResourceUpdate(
        test_case.delta ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{}
                        : resources,
        test_case.delta ? std::vector<std::string>{"remote"} : std::vector<std::string>{},
        test_case.delta);
    EXPECT_EQ(resolve("10.3.4.5").identity_, 44);
    EXPECT_EQ(resolve("f00d::45").identity_, 44);
    EXPECT_TRUE(resolve("10.3.4.5").namedPorts().empty());
    EXPECT_EQ(retained.identity_, 43);
    EXPECT_THAT(retained.namedPorts(),
                testing::ElementsAre(NamedPort{8080, "http"}, NamedPort{9090, "metrics"}));
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, RejectedResourcesRetainMappingsAndApplyValidSiblings) {
  const auto selector =
      TestUtility::parseYaml<cilium::NetworkPolicyResource>("selector: { identities: [43] }");
  const auto policy = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
      "policy: { ingress_per_port_policies: [{port_name: http, rules: [{selectors: [selector]}]}] "
      "}");
  const auto endpoint = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
      "endpoint: { epid: 42, ips: [10.0.0.1], policy: policy, "
      "named_ports: [{name: http, port: 80}] }");
  const auto peer = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
      "peer: { identity: 43, ips: [10.1.2.3, 'f00d::43'], named_ports: [{name: http, port: 80}] }");
  const std::vector<std::pair<std::string, cilium::NetworkPolicyResource>> baseline{
      {"selector", selector}, {"policy", policy}, {"endpoint", endpoint}, {"remote", peer}};
  const struct {
    const char* name;
    const char* resource_name;
    const char* yaml;
  } cases[] = {
      {"invalid Endpoint named port", "endpoint",
       "endpoint: {epid: 42, ips: [10.0.0.1], policy: policy, "
       "named_ports: [{name: http, port: 0}]}"},
      {"missing Endpoint policy", "endpoint",
       "endpoint: {epid: 42, ips: [10.0.0.1], policy: missing-policy}"},
      {"unknown identity", "bad", "peer: {identity: 0, ips: [10.2.3.4]}"},
      {"invalid address", "bad", "peer: {identity: 44, ips: [invalid]}"},
      {"non-prefix bits", "bad", "peer: {identity: 44, ips: [10.2.3.4/24]}"},
      {"invalid IPv6 prefix", "bad", "peer: {identity: 44, ips: ['f00d::/129']}"},
      {"duplicate normalized prefix", "bad", "peer: {identity: 44, ips: [10.1.2.3/32]}"},
      {"duplicate identity", "bad", "peer: {identity: 43, ips: [10.2.3.4]}"},
      {"policy name collision", "policy", "peer: {identity: 44, ips: [10.2.3.4]}"},
      {"endpoint alias collision", "10.0.0.1", "peer: {identity: 44, ips: [10.2.3.4]}"},
  };
  for (bool delta : {false, true}) {
    SCOPED_TRACE(delta ? "delta" : "sotw");
    for (const auto& test_case : cases) {
      SCOPED_TRACE(test_case.name);
      applyResourceUpdate(baseline, {}, false);
      auto changed_selector = selector;
      changed_selector.mutable_selector()->set_identities(0, 99);
      auto resources =
          delta ? std::vector<std::pair<std::string, cilium::NetworkPolicyResource>>{} : baseline;
      if (!delta) {
        std::erase_if(resources, [&](const auto& resource) {
          return resource.first == "selector" || resource.first == "endpoint" ||
                 resource.first == test_case.resource_name;
        });
      }
      resources.emplace_back("selector", changed_selector);
      const uint16_t port = absl::string_view(test_case.resource_name) == "endpoint" ? 80 : 8081;
      if (port == 8081) {
        auto changed_endpoint = endpoint;
        changed_endpoint.mutable_endpoint()->mutable_named_ports(0)->set_port(port);
        resources.emplace_back("endpoint", std::move(changed_endpoint));
      }
      resources.emplace_back(test_case.resource_name,
                             TestUtility::parseYaml<cilium::NetworkPolicyResource>(test_case.yaml));
      EXPECT_THROW(applyResourceUpdate(resources, {}, delta), EnvoyException);
      EXPECT_FALSE(ingressAllowed("10.0.0.1", 43, port));
      EXPECT_TRUE(ingressAllowed("10.0.0.1", 99, port));
      if (port == 8081) {
        EXPECT_FALSE(ingressAllowed("10.0.0.1", 99, 80));
      }
      auto info =
          policy_map_
              ->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow("10.1.2.3")->ip())
              .value();
      EXPECT_EQ(info.identity_, 43);
      EXPECT_THAT(info.namedPorts(), testing::ElementsAre(NamedPort{80, "http"}));
      EXPECT_EQ(
          policy_map_
              ->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow("10.2.3.4")->ip())
              .value()
              .identity_,
          ID::UNKNOWN);
    }
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, NewPeerStreamsReplaceAcceptedMappingsAfterFirstValidUpdate) {
  for (bool delta : {false, true}) {
    SCOPED_TRACE(delta ? "delta" : "sotw");
    auto peer = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
        "peer: {identity: 43, ips: [10.1.2.3], named_ports: [{name: http, port: 80}]}");
    resetStreamForTest();
    applyResourceUpdate({{"remote", peer}}, {}, delta);
    auto address = Network::Utility::parseInternetAddressNoThrow("10.1.2.3");
    const auto retained = policy_map_->resolvePolicyInfo(address->ip()).value();
    resetStreamForTest();
    auto invalid_peer = peer;
    invalid_peer.mutable_peer()->set_ips(0, "invalid");
    EXPECT_THROW(applyResourceUpdate({{"remote", invalid_peer}}, {}, delta), EnvoyException);
    EXPECT_EQ(policy_map_->resolvePolicyInfo(address->ip()).value().identity_, 43);
    applyResourceUpdate({}, {}, delta);
    EXPECT_EQ(policy_map_->resolvePolicyInfo(address->ip()).value().identity_, ID::UNKNOWN);
    peer.mutable_peer()->set_identity(44);
    applyResourceUpdate({{"remote", peer}}, {}, delta);
    EXPECT_EQ(policy_map_->resolvePolicyInfo(address->ip()).value().identity_, 44);
    EXPECT_EQ(retained.identity_, 43);
    EXPECT_THAT(retained.namedPorts(), testing::ElementsAre(NamedPort{80, "http"}));
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, PeerReplacementsCanTransferAddressesInEitherOrder) {
  for (bool reverse : {false, true}) {
    SCOPED_TRACE(reverse);
    auto first = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
        "peer: {identity: 43, ips: [10.1.2.3]}");
    auto second = TestUtility::parseYaml<cilium::NetworkPolicyResource>(
        "peer: {identity: 44, ips: [10.1.2.4]}");
    applyResourceUpdate({{"first", first}, {"second", second}}, {}, false);
    first.mutable_peer()->set_ips(0, "10.1.2.4");
    second.mutable_peer()->set_ips(0, "10.1.2.3");
    std::vector<std::pair<std::string, cilium::NetworkPolicyResource>> update{{"first", first},
                                                                              {"second", second}};
    if (reverse) {
      std::reverse(update.begin(), update.end());
    }
    applyResourceUpdate(update, {}, true);
    EXPECT_EQ(
        policy_map_
            ->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow("10.1.2.3")->ip())
            .value()
            .identity_,
        44);
    EXPECT_EQ(
        policy_map_
            ->resolvePolicyInfo(Network::Utility::parseInternetAddressNoThrow("10.1.2.4")->ip())
            .value()
            .identity_,
        43);
  }
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaRejectsNamedPortPolicyWithNumericPort) {
  EXPECT_THAT_THROWS_MESSAGE(
      deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      ingress_per_port_policies:
      - port: 8080
        port_name: http
)EOF"),
      EnvoyException,
      testing::HasSubstr("PortNetworkPolicy: Named port 'http' must have zero port and end port"));
}

TEST_F(CiliumNetworkPolicyDeltaTest, DeltaNamedPortVerdictPrecedence) {
  EXPECT_NO_THROW(deltaUpdateFromYaml(R"EOF(system_version_info: "1"
resources:
- name: "id-43"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 43 ]
- name: "id-44"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 44 ]
- name: "id-45"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 45 ]
- name: "id-46"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    selector:
      identities: [ 46 ]
- name: "endpoint-for-policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    endpoint:
      ips: [ "10.1.2.3" ]
      epid: 42
      policy: "policy-42"
- name: "policy-42"
  version: "1"
  resource:
    "@type": type.googleapis.com/cilium.NetworkPolicyResource
    policy:
      egress_per_port_policies:
      - port: 8080
        rules:
        - precedence: 100
          selectors: [ "id-43" ]
        - precedence: 100
          deny: true
          selectors: [ "id-44" ]
        - precedence: 100
          selectors: [ "id-45" ]
      - port_name: low-deny
        rules:
        - precedence: 50
          deny: true
          selectors: [ "id-43" ]
      - port_name: equal-deny
        rules:
        - precedence: 100
          deny: true
          selectors: [ "id-43" ]
      - port_name: high-allow
        rules:
        - precedence: 200
          selectors: [ "id-44" ]
      - port_name: high-deny
        rules:
        - precedence: 200
          deny: true
          selectors: [ "id-45" ]
      - port_name: named-only
        rules:
        - precedence: 100
          selectors: [ "id-46" ]
)EOF"));

  // Lower named precedence does not replace a concrete allow.
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 8080, {{8080, "low-deny"}}));
  // Equal named precedence also retains the concrete verdict.
  EXPECT_TRUE(egressAllowed("10.1.2.3", 43, 8080, {{8080, "equal-deny"}}));
  // Higher named precedence replaces the concrete verdict in either direction.
  EXPECT_TRUE(egressAllowed("10.1.2.3", 44, 8080, {{8080, "high-allow"}}));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 45, 8080, {{8080, "high-deny"}}));
  // A named verdict is used when the concrete lookup has no verdict.
  EXPECT_TRUE(egressAllowed("10.1.2.3", 46, 8080, {{8080, "named-only"}}));
  // A mismatching concrete port does not activate the named policy; no verdict means default deny.
  EXPECT_FALSE(egressAllowed("10.1.2.3", 46, 8080, {{9090, "named-only"}}));
  EXPECT_FALSE(egressAllowed("10.1.2.3", 47, 8080, NamedPorts{}));
}

} // namespace Cilium
} // namespace Envoy
