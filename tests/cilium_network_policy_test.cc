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
namespace {

class CiliumNetworkPolicyTest : public ::testing::Test {
protected:
  CiliumNetworkPolicyTest() {
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumNetworkPolicyTest() override {}

  void SetUp() override {
    ON_CALL(factory_context_.transport_socket_factory_context_, stats())
        .WillByDefault(testing::ReturnRef(store_));

    // Mock SDS secrets with a real implementation, which will not return anything if there is no SDS server.
    // This is only useful for testing functionality with a missing secret.
    auto& secret_manager = factory_context_.server_factory_context_.cluster_manager_.cluster_manager_factory_.secretManager();
    ON_CALL(secret_manager, findOrCreateGenericSecretProvider(_, _, _, _))
      .WillByDefault(Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,
			       const std::string& config_name,
			       Server::Configuration::TransportSocketFactoryContext& secret_provider_context,
			       Init::Manager& init_manager) {
	auto secret_provider = Secret::GenericSecretSdsApi::create(secret_provider_context, sds_config_source,
								   config_name, [](){});
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
    policy_map_->onConfigUpdate(decoded_resources.refvec_, message.version_info());
    return message.version_info();
  }

  testing::AssertionResult Allowed(bool ingress, const std::string& pod_ip, uint64_t remote_id,
                                   uint16_t port, Http::TestRequestHeaderMapImpl&& headers) {
    auto policy = policy_map_->GetPolicyInstance(pod_ip);
    if (policy == nullptr)
      return testing::AssertionFailure() << "Policy not found for " << pod_ip;
    Cilium::AccessLog::Entry log_entry;
    return policy->Allowed(ingress, port, remote_id, headers, log_entry)
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
  EXPECT_NO_THROW(policy_map_->onConfigUpdate({}, "1"));
}

TEST_F(CiliumNetworkPolicyTest, SimplePolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
}

TEST_F(CiliumNetworkPolicyTest, OverlappingPortRange) {
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - "10.1.2.3"
  endpoint_id: 42
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 43 ]
  - port: 40
    end_port: 99
    rules:
    - remote_policies: [ 43 ]
)EOF"),
                            EnvoyException, "PortNetworkPolicy: Overlapping port range 40-99");

  // No ingress is allowed:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, OverlappingPortRanges) {
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
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
    - remote_policies: [ 43 ]
)EOF"),
                            EnvoyException, "PortNetworkPolicy: Overlapping port range 4040-9999");

  // No ingress is allowed:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, DuplicatePorts) {
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
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
)EOF"),
                            EnvoyException, "PortNetworkPolicy: Duplicate port number 80");

  // No ingress is allowed:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
  // No egress is allowed:
  EXPECT_FALSE(EgressAllowed("10.1.2.3", 43, 8080));
}

TEST_F(CiliumNetworkPolicyTest, DuplicatePortRange) {
  EXPECT_THROW_WITH_MESSAGE(updateFromYaml(R"EOF(version_info: "1"
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
)EOF"),
                            EnvoyException, "PortNetworkPolicy: Duplicate port number 80");

  // No ingress is allowed:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80));
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
      EnvoyException, "PortNetworkPolicy: Invalid port range, end port is less than port 80-60");

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
  // Allowed remote ID, port, & path:
  EXPECT_TRUE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Wrong remote ID:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 40, 80, {{":path", "/allowed"}}));
  // Wrong port:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 8080, {{":path", "/allowed"}}));
  // Wrong path:
  EXPECT_FALSE(IngressAllowed("10.1.2.3", 43, 80, {{":path", "/notallowed"}}));
}

} // namespace
} // namespace Cilium
} // namespace Envoy
