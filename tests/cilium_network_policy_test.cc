#include "source/common/common/logger.h"
#include "source/common/config/decoded_resource_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/secret/secret_provider_impl.h"

#include "test/mocks/server/factory_context.h"
#include "test/test_common/environment.h"

#include "cilium/network_policy.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Cilium {

class CiliumNetworkPolicyTest : public ::testing::Test {
protected:
  CiliumNetworkPolicyTest() {
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumNetworkPolicyTest() override {}

  void SetUp() override {
    // Mock SDS secrets with a real implementation, which will not return anything if there is no
    // SDS server. This is only useful for testing functionality with a missing secret.
    auto& secret_manager = factory_context_.server_factory_context_.cluster_manager_
                               .cluster_manager_factory_.secretManager();
    ON_CALL(secret_manager, findOrCreateGenericSecretProvider(_, _, _, _))
        .WillByDefault(
            Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,
                      const std::string& config_name,
                      Server::Configuration::TransportSocketFactoryContext& secret_provider_context,
                      Init::Manager& init_manager) {
              auto secret_provider = Secret::GenericSecretSdsApi::create(
                  secret_provider_context, sds_config_source, config_name, []() {});
              init_manager.add(*secret_provider->initTarget());
              return secret_provider;
            }));

    policy_map_ = std::make_shared<NetworkPolicyMap>(factory_context_);
  }

  void TearDown() override {
    ASSERT(policy_map_.use_count() == 1);
    policy_map_.reset();
  }

  std::string updateFromYaml(const std::string& config) {
    envoy::service::discovery::v3::DiscoveryResponse message;
    MessageUtil::loadFromYaml(config, message, ProtobufMessage::getNullValidationVisitor());
    NetworkPolicyDecoder network_policy_decoder;
    const auto decoded_resources = Config::DecodedResourcesWrapper(
        network_policy_decoder, message.resources(), message.version_info());
    EXPECT_TRUE(
        policy_map_->onConfigUpdate(decoded_resources.refvec_, message.version_info()).ok());
    return message.version_info();
  }

  testing::AssertionResult Validate(const std::string& pod_ip, const std::string& expected) {
    auto& policy = policy_map_->GetPolicyInstance(pod_ip);
    if (policy == nullptr)
      return testing::AssertionFailure() << "Policy not found for " << pod_ip;
    auto str = policy->String();
    if (str != expected) {
      return testing::AssertionFailure() << "Policy:\n"
                                         << str << "Does not match expected:\n"
                                         << expected;
    }
    return testing::AssertionSuccess();
  }

  testing::AssertionResult Allowed(bool ingress, const std::string& pod_ip, uint64_t remote_id,
                                   uint16_t port, Http::TestRequestHeaderMapImpl&& headers) {
    auto policy = policy_map_->GetPolicyInstance(pod_ip);
    if (policy == nullptr)
      return testing::AssertionFailure() << "Policy not found for " << pod_ip;
    Cilium::AccessLog::Entry log_entry;
    return policy->allowed(ingress, remote_id, port, headers, log_entry)
               ? testing::AssertionSuccess()
               : testing::AssertionFailure();
  }
  testing::AssertionResult IngressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                          uint16_t port,
                                          Http::TestRequestHeaderMapImpl&& headers = {}) {
    return Allowed(true, pod_ip, remote_id, port, std::move(headers));
  }
  testing::AssertionResult EgressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                         uint16_t port,
                                         Http::TestRequestHeaderMapImpl&& headers = {}) {
    return Allowed(false, pod_ip, remote_id, port, std::move(headers));
  }

  NiceMock<Server::Configuration::MockFactoryContext> factory_context_;
  std::shared_ptr<NetworkPolicyMap> policy_map_;
  NiceMock<Stats::TestUtil::TestStore> store_;
};

TEST_F(CiliumNetworkPolicyTest, EmptyPolicyUpdate) {
  EXPECT_TRUE(policy_map_->onConfigUpdate({}, "1").ok());
  EXPECT_FALSE(Validate("10.1.2.3", "")); // Policy not found
}

TEST_F(CiliumNetworkPolicyTest, SimplePolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(Validate("10.1.2.3", "")); // Policy not found
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
      - remotes: [42]
      - remotes: [45]
    [40-79]:
    - rules:
      - remotes: [43]
    [80-80]:
    - rules:
      - remotes: [44]
    - rules:
      - remotes: [43]
    [81-91]:
    - rules:
      - remotes: [43]
    [92-92]:
    - rules:
      - remotes: []
        can_short_circuit: false
        deny: true
      can_short_circuit: false
    - rules:
      - remotes: [43]
    [93-99]:
    - rules:
      - remotes: [43]
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress from 42 is allowed on port 23
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 42, 23));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 23));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 23));

  // port 92 is denied from everyone
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 42, 92));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 92));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 92));

  // Ingress from 43 is allowed on all ports of the range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 39));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 40));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 99));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 100));

  // 44 is only allowed to port 80
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 39));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 40));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 81));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 99));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 100));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 44, 8080));

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

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress from 42 is allowed on port 23
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 42, 23));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 23));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 23));

  // port 92 is denied from everyone
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 42, 92));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 92));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 92));

  // Ingress from 43 is allowed on all ports of the range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 39));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 40));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 99));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 100));

  // 44 is only allowed to port 80
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 39));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 40));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 81));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 99));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 100));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 44, 8080));
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
    - rules:
      - remotes: [44]
    [8081-9999]:
    - rules:
      - remotes: [44]
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress from 43 is allowed to ports 80-8080 only:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8081));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9998));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 44, 8080));

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
    - rules:
      - remotes: [43]
    [8081-9999]:
    - rules:
      - remotes: [44]
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress from 43 is allowed to ports 80-8080 only:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4039));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4040));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4041));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8081));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9998));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9999));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 10000));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 44, 8080));
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
    - rules:
      - remotes: [43]
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress from 43 is allowed on port 80 only:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 8080));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
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
    - rules:
      - remotes: [43]
    [81-8080]:
    - rules:
      - remotes: [43]
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Ingress is allowed:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 79));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 81));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8079));
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8081));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
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
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
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
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80));
  // Allowed port:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path is ignored:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80));
}

TEST_F(CiliumNetworkPolicyTest, HttpPolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

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
  wildcard_rules: []
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Wrong path:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));

  // 3rd update with Ingress deny rules
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
    - rules:
      - remotes: []
        can_short_circuit: false
        deny: true
      can_short_circuit: false
    [81-10000]:
    - rules:
      - remotes: []
        can_short_circuit: false
        deny: true
      can_short_circuit: false
  wildcard_rules: []
egress:
  rules:
    [80-80]:
    - rules:
      - remotes: [43,44]
        http_rules:
        - headers:
          - name: ":path"
            regex: <hidden>
  wildcard_rules: []
)EOF";

  EXPECT_TRUE(Validate("10.1.2.3", expected));

  // Denied remote ID, port, & path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Denied remote ID & wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID, port, & path:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Wrong path:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
}

TEST_F(CiliumNetworkPolicyTest, TcpPolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

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
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path does not matter:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

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
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Path does not matter
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // Allowed remote ID & port:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 44, 80, {{":path", "/public"}}));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Wrong port:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080, {{":path", "/public"}}));
  // Path does not matter:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
}

TEST_F(CiliumNetworkPolicyTest, PortRanges) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));

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
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  // Path does not matter
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
  // Port within the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4040));
  // Port at the end of the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8081));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80));

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
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80));
  // Path does not matter
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
  // Port within the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 4040));
  // Port at the end of the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 8080));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8081));

  // Allowed remote ID & port:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 44, 9000));
  // Port within the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 44, 9500));
  // Port at the end of the range:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 44, 9999));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 8999));
  // Port out of range:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 10000));

  // Wrong remote IDs:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 44, 80));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9000));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9500));
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 9999));

  // Allowed remote ID & port:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80));
  // Path does not matter:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 44, 80));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80));
  // Port within the range:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 85));
  // Port at the end of the range:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 90));
  // Port out of range:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 79));
  // Port out of range:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 91));

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
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/publicz"}}));
  // Allowed remote ID & port:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 44, 80, {{":path", "/allows"}}));
  // Wrong remote ID:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 40, 80, {{":path", "/public"}}));
  // Port within the range:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 85, {{":path", "/allows"}}));
  // Port at the end of the range:
  EXPECT_TRUE(EgressAllowed("10.1.2.3", 43, 90, {{":path", "/public"}}));
  // Port out of range:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 79, {{":path", "/allows"}}));
  // Port out of range:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 91, {{":path", "/public"}}));
}

TEST_F(CiliumNetworkPolicyTest, HttpPolicyUpdateToMissingSDS) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(policy_map_->exists("10.1.2.3"));
  // No policy for the pod
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));

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
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));

  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 80, {{":path", "/public"}}));

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
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
}

} // namespace Cilium
} // namespace Envoy
