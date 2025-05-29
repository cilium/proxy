#include <gmock/gmock-spec-builders.h>
#include <spdlog/common.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/init/manager.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/service/discovery/v3/discovery.pb.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"

#include "source/common/common/assert.h"
#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
#include "source/common/config/decoded_resource_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"

#include "test/common/stats/stat_test_utility.h"
#include "test/mocks/server/admin.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/network_policy.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace Cilium {

#define ON_CALL_SDS_SECRET_PROVIDER(SECRET_MANAGER, PROVIDER_TYPE, API_TYPE)                       \
  ON_CALL(SECRET_MANAGER, findOrCreate##PROVIDER_TYPE##Provider(_, _, _, _))                       \
      .WillByDefault(                                                                              \
          Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,                \
                    const std::string& config_name,                                                \
                    Server::Configuration::TransportSocketFactoryContext& secret_provider_context, \
                    Init::Manager& init_manager) {                                                 \
            auto secret_provider = Secret::API_TYPE##SdsApi::create(                               \
                secret_provider_context, sds_config_source, config_name, []() {});                 \
            init_manager.add(*secret_provider->initTarget());                                      \
            return secret_provider;                                                                \
          }))

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
    auto& secret_manager = factory_context_.server_factory_context_.cluster_manager_
                               .cluster_manager_factory_.secretManager();
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager, TlsCertificate, TlsCertificate);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager, CertificateValidationContext,
                                CertificateValidationContext);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager, TlsSessionTicketKeysContext, TlsSessionTicketKeys);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager, GenericSecret, GenericSecret);

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
    const auto decoded_resources_or_error = Config::DecodedResourcesWrapper::create(
        network_policy_decoder, message.resources(), message.version_info());
    THROW_IF_NOT_OK_REF(decoded_resources_or_error.status());
    const auto decoded_resources = std::move(decoded_resources_or_error.value().get());

    EXPECT_TRUE(policy_map_->getImpl()
                    .onConfigUpdate(decoded_resources->refvec_, message.version_info())
                    .ok());
    return message.version_info();
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

  testing::AssertionResult allowed(bool ingress, const std::string& pod_ip, uint64_t remote_id,
                                   uint16_t port, Http::TestRequestHeaderMapImpl&& headers) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);
    Cilium::AccessLog::Entry log_entry;
    return policy.allowed(ingress, proxy_id_, remote_id, port, headers, log_entry)
               ? testing::AssertionSuccess()
               : testing::AssertionFailure();
  }
  testing::AssertionResult ingressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                          uint16_t port,
                                          Http::TestRequestHeaderMapImpl&& headers = {}) {
    return allowed(true, pod_ip, remote_id, port, std::move(headers));
  }
  testing::AssertionResult egressAllowed(const std::string& pod_ip, uint64_t remote_id,
                                         uint16_t port,
                                         Http::TestRequestHeaderMapImpl&& headers = {}) {
    return allowed(false, pod_ip, remote_id, port, std::move(headers));
  }

  testing::AssertionResult tlsAllowed(bool ingress, const std::string& pod_ip, uint64_t remote_id,
                                      uint16_t port, absl::string_view sni,
                                      bool& tls_socket_required, bool& raw_socket_allowed) {
    const auto& policy = policy_map_->getPolicyInstance(pod_ip, false);

    auto port_policy = policy.findPortPolicy(ingress, port);
    const Envoy::Ssl::ContextConfig* config = nullptr;

    // TLS context lookup does not check SNI
    tls_socket_required = false;
    raw_socket_allowed = false;
    Envoy::Ssl::ContextSharedPtr ctx =
        !ingress ? port_policy.getClientTlsContext(proxy_id_, remote_id, sni, &config,
                                                   raw_socket_allowed)
                 : port_policy.getServerTlsContext(proxy_id_, remote_id, sni, &config,
                                                   raw_socket_allowed);

    // separate policy lookup for validation
    bool allowed = policy.allowed(ingress, proxy_id_, remote_id, sni, port);

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

  std::string updatesRejectedStatName() {
    return policy_map_->getImpl().stats_.updates_rejected_.name();
  }

  NiceMock<Server::Configuration::MockFactoryContext> factory_context_;
  std::shared_ptr<NetworkPolicyMap> policy_map_;
  NiceMock<Stats::TestUtil::TestStore> store_;
  uint32_t proxy_id_ = 42;
};

TEST_F(CiliumNetworkPolicyTest, UpdatesRejectedStatName) {
  EXPECT_EQ("cilium.policy.updates_rejected", updatesRejectedStatName());
}

TEST_F(CiliumNetworkPolicyTest, EmptyPolicyUpdate) {
  EXPECT_TRUE(policy_map_->getImpl().onConfigUpdate({}, "1").ok());
  EXPECT_FALSE(validate("10.1.2.3", "")); // Policy not found
}

TEST_F(CiliumNetworkPolicyTest, SimplePolicyUpdate) {
  std::string version;
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "0"
)EOF"));
  EXPECT_EQ(version, "0");
  EXPECT_FALSE(validate("10.1.2.3", "")); // Policy not found
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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
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
        proxy_id: 42
    [81-10000]:
    - rules:
      - remotes: []
        proxy_id: 42
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
        proxy_id: 99
    [81-10000]:
    - rules:
      - remotes: []
        proxy_id: 99
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
    - rules:
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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
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
    - rules:
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
  wildcard_rules: []
egress:
  rules: []
  wildcard_rules: []
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

  // TLS SNI update
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
      server_names: [ "cilium.io", "example.com" ]
)EOF"));
  EXPECT_EQ(version, "2");
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

  // TLS Interception update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
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
  EXPECT_EQ(version, "2");
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

  // TLS Termination update
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
      server_names: [ "cilium.io", "example.com" ]
      downstream_tls_context:
        tls_sds_secret: "secret1"
)EOF"));
  EXPECT_EQ(version, "2");
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

  // TLS Origination update
  EXPECT_NO_THROW(version = updateFromYaml(R"EOF(version_info: "2"
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
  EXPECT_EQ(version, "2");
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

TEST_F(CiliumNetworkPolicyTest, SNIPatternMatching) {
  // Test empty pattern
  SniPattern empty("");
  EXPECT_FALSE(empty.matches("example.com"));
  EXPECT_FALSE(empty.matches("EXAMPLE.COM"));
  EXPECT_FALSE(empty.matches("www.example.com"));
  EXPECT_FALSE(empty.matches("notexample.com"));
  EXPECT_FALSE(empty.matches(""));

  // Test exact matches
  SniPattern exact("example.com");
  EXPECT_TRUE(exact.matches("example.com"));
  EXPECT_TRUE(exact.matches("EXAMPLE.COM"));
  EXPECT_FALSE(exact.matches("www.example.com"));
  EXPECT_FALSE(exact.matches("notexample.com"));
  EXPECT_FALSE(exact.matches(""));

  // Test wildcard matches
  SniPattern wild("*.example.com");
  EXPECT_TRUE(wild.matches("foo.example.com"));
  EXPECT_TRUE(wild.matches("bar.example.com"));
  EXPECT_TRUE(wild.matches("FOO.EXAMPLE.COM"));
  EXPECT_FALSE(wild.matches("example.com"));
  EXPECT_FALSE(wild.matches("foo.bar.example.com"));
  EXPECT_FALSE(wild.matches("fooexample.com"));
  EXPECT_FALSE(wild.matches(""));

  // Test subdomain wildcard matches
  SniPattern subwild("*.sub.example.com");
  EXPECT_TRUE(subwild.matches("foo.sub.example.com"));
  EXPECT_TRUE(subwild.matches("bar.sub.example.com"));
  EXPECT_FALSE(subwild.matches("sub.example.com"));
  EXPECT_FALSE(subwild.matches("foo.example.com"));
  EXPECT_FALSE(subwild.matches("foo.bar.sub.example.com"));

  // Test subdomain double wildcard matches
  SniPattern double_wildcard("**.sub.example.com");
  EXPECT_TRUE(double_wildcard.matches("foo.sub.example.com"));
  EXPECT_TRUE(double_wildcard.matches("bar.sub.example.com"));
  EXPECT_FALSE(double_wildcard.matches("sub.example.com"));
  EXPECT_FALSE(double_wildcard.matches("foo.example.com"));
  EXPECT_TRUE(double_wildcard.matches("foo.bar.sub.example.com"));

  // Test with unsupported wildcard label
  SniPattern wildcard_label("*example.com");
  EXPECT_FALSE(wildcard_label.matches("foo.example.com"));
  EXPECT_FALSE(wildcard_label.matches("bar.example.com"));
  EXPECT_FALSE(wildcard_label.matches("FOO.EXAMPLE.COM"));
  EXPECT_FALSE(wildcard_label.matches("example.com"));
  EXPECT_FALSE(wildcard_label.matches("foo.bar.example.com"));
  EXPECT_FALSE(wildcard_label.matches("fooexample.com"));
  EXPECT_FALSE(wildcard_label.matches(""));
}

} // namespace Cilium
} // namespace Envoy
