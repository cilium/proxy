#include <gmock/gmock-spec-builders.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <spdlog/common.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
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
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/secret/sds_api.h"

#include "test/common/stats/stat_test_utility.h"
#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/admin.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/utility.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/network_policy.h"

namespace Envoy {
namespace Cilium {

#define ON_CALL_SDS_SECRET_PROVIDER(SECRET_MANAGER, PROVIDER_TYPE, API_TYPE)                       \
  ON_CALL(SECRET_MANAGER, findOrCreate##PROVIDER_TYPE##Provider(_, _, _, _))                       \
      .WillByDefault(Invoke([](const envoy::config::core::v3::ConfigSource& sds_config_source,     \
                               const std::string& config_name,                                     \
                               Server::Configuration::ServerFactoryContext& server_context,        \
                               Init::Manager& init_manager) {                                      \
        auto secret_provider = Secret::API_TYPE##SdsApi::create(server_context, sds_config_source, \
                                                                config_name, []() {});             \
        init_manager.add(*secret_provider->initTarget());                                          \
        return secret_provider;                                                                    \
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
    ON_CALL(factory_context_.server_factory_context_, secretManager())
        .WillByDefault(ReturnRef(secret_manager_));

    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, TlsCertificate, TlsCertificate);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, CertificateValidationContext,
                                CertificateValidationContext);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, TlsSessionTicketKeysContext, TlsSessionTicketKeys);
    ON_CALL_SDS_SECRET_PROVIDER(secret_manager_, GenericSecret, GenericSecret);

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
    // test network layer policy first
    if (!policy.allowed(ingress, proxy_id_, remote_id, "", port)) {
      return testing::AssertionFailure();
    }
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
  NiceMock<Secret::MockSecretManager> secret_manager_;
  std::shared_ptr<NetworkPolicyMap> policy_map_;
  NiceMock<Stats::TestUtil::TestStore> store_;
  uint16_t proxy_id_ = 42;
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
        name: "default allow rule"
        precedence: 9
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
        name: "default allow rule"
        precedence: 9
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        deny: true
        precedence: 900
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        deny: true
        precedence: 900
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
      - remotes: [43,44]
        precedence: 999
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        deny: true
        precedence: 900
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected9));

  // Remote 43 is promoted above deny by pass.
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        deny: true
        precedence: 900
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected10));

  // Pass from wildcard port should promote remote 43 above deny on port 80.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  // Remote 44 is denied due to only 43 being promoted.
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
      - remotes: [43,44]
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allowed"
      - remotes: []
        deny: true
        precedence: 900
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected11));

  // Both IDs are passed to the lower allow despite the intermediate deny.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allowed"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allowed"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allowed"}}));

  //
  // 12th update: non-pass rule shadowing inside a pass tier
  //
  // The pass rule is required to enable tier processing, but it targets only
  // remote 45 so the tier is not wildcard-pass and does not pre-shadow 43/44.
  // Within this tier:
  // - A higher-precedence deny for remote 44 establishes a final verdict for 44.
  // - A lower-precedence allow for [43,44] must have 44 removed due to shadowing.
  // - A second allow at the same precedence for [43] must keep 43, confirming
  //   no same-precedence identity shadowing between allow rules.
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/allow-c"
      - remotes: [44]
        deny: true
        precedence: 900
      - remotes: [43]
        precedence: 800
        http_rules:
        - headers:
          - name: ":path"
            value: "/allow-b"
      - remotes: [43]
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
  // Remote 44 is denied by the higher-precedence deny and removed from allow-a.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-a"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-b"}}));
  // Pass remote 45 does not match /allow-a because only /allow-c is promoted for it.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allow-a"}}));
  // Wildcard allow at precedence 700 is promoted to precedence 999 only for pass remote 45.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/allow-c"}}));
  // Non-pass remotes not already denied at higher precedence still match the
  // original wildcard rule at precedence 700.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/allow-c"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/allow-c"}}));

  //
  // 13th update: inherited wildcard current-tier pass fully shadowed
  //
  // Wildcard port has a current-tier pass for remote 43, and specific port has
  // a higher precedence pass for the same remote on the same tier. When the
  // wildcard pass is inherited, it is fully shadowed and skipped, as evidenced by the
  // precedence of the passed-to rule for remote 43, which is 999 rather than 899.
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
        precedence: 999
        http_rules:
        - headers:
          - name: ":path"
            value: "/shadowed-inherited-pass"
      - remotes: []
        deny: true
        precedence: 800
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected13));

  // Remote 43 is promoted above deny due to the specific-port pass.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/shadowed-inherited-pass"}}));
  // Remote 44 remains denied by the intermediate deny.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/shadowed-inherited-pass"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/shadowed-inherited-pass"}}));

  //
  // 14th update: multiple wildcard pass tiers inherited by a specific port
  //
  // Wildcard port contributes two pass tiers:
  // Tier boundaries are inclusive.
  // - tier 1 pass (1300/1000) for remote 41: tier boundaries [1300..1000]
  // - tier 2 pass (900/700) for remote 42: tier boundaries [999..700]
  // For port 80:
  // - deny at 850 is within tier 2, so it is promoted by tier 1 pass for remote 41 to 1150
  // - allow [41,42,43] at 600 is split and promoted by both tiers:
  //   - 41 to tier 1 precedence 900
  //   - 42 to tier 2 precedence 800
  //   - 43 remains at tier 3 at precedence 600
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
    - precedence: 850
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
        deny: true
        precedence: 1150
      - remotes: []
        deny: true
        precedence: 850
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected14));

  // Remote 41 hits the promoted deny from tier 1.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 41, 80, {{":path", "/multi-tier"}}));
  // Remote 42 is promoted by the lower wildcard tier, but remains below deny.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 42, 80, {{":path", "/multi-tier"}}));
  // Remote 43 is not promoted and is denied.
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

  // Failed update must leave policy unchanged from version 10.
  EXPECT_TRUE(validate("10.1.2.3", expected14));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 41, 80, {{":path", "/multi-tier"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 42, 80, {{":path", "/multi-tier"}}));

  //
  // 16th update: inherited wildcard pass skips remaining rules on that tier
  //
  // Wildcard port has a wildcard pass (2000/700), which is inherited for port 80.
  // Rules in that same tier [1999..700] are skipped; a lower-tier rule at 600 is
  // retained and promoted to 1900 by the inherited wildcard pass.
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
      - remotes: [43,44]
        precedence: 1900
        http_rules:
        - headers:
          - name: ":path"
            value: "/promoted-after-skip"
egress:
  rules: []
)EOF";

  EXPECT_TRUE(validate("10.1.2.3", expected16));

  // Both remotes are allowed by the promoted lower-tier rule.
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/promoted-after-skip"}}));
  EXPECT_TRUE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/promoted-after-skip"}}));
  // Tier rule at 800 is skipped by inherited wildcard pass.
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 44, 80, {{":path", "/should-skip"}}));
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/promoted-after-skip"}}));

  //
  // 17th update: Shadowed rules are eliminated
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
      - remotes: [43]
        deny: true
        precedence: 999
      - remotes: [44]
        precedence: 699
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
  // Rule at 800 is shadowed by higher precedence deny
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 43, 80, {{":path", "/should-skip"}}));
  // inapplicable identity
  EXPECT_FALSE(ingressAllowed("10.1.2.3", 45, 80, {{":path", "/partially-skipped"}}));
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

} // namespace Cilium
} // namespace Envoy
