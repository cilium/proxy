#include <fmt/format.h>

#include <string>
#include <vector>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/config/listener/v3/listener.pb.h"
#include "envoy/grpc/status.h"
#include "envoy/http/codec.h"
#include "envoy/network/address.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/common/assert.h"
#include "source/common/protobuf/utility.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/config/utility.h"
#include "test/integration/base_integration_test.h"
#include "test/integration/fake_upstream.h"
#include "test/test_common/resources.h"
#include "test/test_common/utility.h"

#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/nphds.pb.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace {

const std::string NetworkPolicyTypeUrl = "type.googleapis.com/cilium.NetworkPolicy";

const std::string NetworkPolicyHostsTypeUrl = "type.googleapis.com/cilium.NetworkPolicyHosts";

const std::string policy1 = R"EOF(
  endpoint_ips:
  - '10.1.1.1'
  - 'face::1:1:1'
  endpoint_id: 2048
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 222 ]
)EOF";

const std::string policy2 = R"EOF(
  endpoint_ips:
  - '10.2.2.2'
  - 'face::2:2:2'
  endpoint_id: 4096
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 111 ]
)EOF";

const std::string policy_host1 = R"EOF(
  policy: 111
  host_addresses: [ "10.1.1.1", "f00d::1:1:1" ]
)EOF";

const std::string policy_host2 = R"EOF(
  policy: 222
  host_addresses: [ "10.2.2.2", "f00d::2:2:2" ]
)EOF";

class BpfMetadataIntegrationTest : public BaseIntegrationTest,
                                   public Grpc::GrpcClientIntegrationParamTest {
public:
  BpfMetadataIntegrationTest()
      : BaseIntegrationTest(ipVersion(), ConfigHelper::baseConfig() + R"EOF(
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster_0
)EOF") {
    skip_tag_extraction_rule_check_ = true;
  }

  ~BpfMetadataIntegrationTest() override { resetConnections(); }

  void setGrpcServiceHelper(envoy::config::core::v3::GrpcService& grpc_service,
                            const std::string& cluster_name,
                            Network::Address::InstanceConstSharedPtr address) {
    setGrpcService(grpc_service, cluster_name, address);
  }

  void setUpGrpcLds() {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      listener_config_.Swap(bootstrap.mutable_static_resources()->mutable_listeners(0));
      listener_config_.set_name(listener_name_);
      bootstrap.mutable_static_resources()->mutable_listeners()->Clear();

      auto* lds_config_source = bootstrap.mutable_dynamic_resources()->mutable_lds_config();
      lds_config_source->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
      lds_config_source->mutable_ads();
    });
  }

  // Inject the cilium.bpf_metadata listener filter with config_source into the listener.
  void addBpfMetadataListenerFilter(envoy::config::listener::v3::Listener& listener, bool) {
    auto* listener_filter = listener.add_listener_filters();
    listener_filter->set_name("cilium.bpf_metadata");

    ::cilium::BpfMetadata bpf_config;
    bpf_config.set_is_ingress(false);
    bpf_config.set_use_nphds(true);

    auto* config_source = bpf_config.mutable_cilium_config_source();
    config_source->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    config_source->mutable_ads();

    listener_filter->mutable_typed_config()->PackFrom(bpf_config);
  }

  void initialize() override {
    use_lds_ = false;
    setUpstreamCount(1);
    defer_listener_finalization_ = true;

    config_helper_.addConfigModifier([](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // Add the ADS gRPC cluster.
      auto* ads_cluster = bootstrap.mutable_static_resources()->add_clusters();
      ads_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      ads_cluster->set_name("ads_cluster");
      ConfigHelper::setHttp2(*ads_cluster);

      auto* cds_config = bootstrap.mutable_dynamic_resources()->mutable_cds_config();
      cds_config->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
      cds_config->mutable_ads();

      // Configure ADS in bootstrap.
      auto* ads_config = bootstrap.mutable_dynamic_resources()->mutable_ads_config();
      ads_config->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
      ads_config->set_transport_api_version(envoy::config::core::v3::V3);
      envoy::config::core::v3::GrpcService* grpc_service = ads_config->add_grpc_services();
      grpc_service->mutable_envoy_grpc()->set_cluster_name("ads_cluster");
      ads_config->set_set_node_on_first_message_only(true);
    });

    // Must be last modifier — it removes static listeners.
    setUpGrpcLds();

    BaseIntegrationTest::initialize();
  }

  void createUpstreams() override {
    BaseIntegrationTest::createUpstreams();
    // ADS upstream (fake_upstreams_[1]).
    addFakeUpstream(Envoy::Http::CodecType::HTTP2);
  }

  FakeUpstream& getAdsFakeUpstream() const { return *fake_upstreams_[1]; }

  void createAdsStream() {
    AssertionResult result =
        getAdsFakeUpstream().waitForHttpConnection(*dispatcher_, ads_connection_);
    RELEASE_ASSERT(result, result.message());
    auto result2 = ads_connection_->waitForNewStream(*dispatcher_, ads_stream_);
    RELEASE_ASSERT(result2, result2.message());
    ads_stream_->startGrpcStream();
  }

  void sendCdsResponse(const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_type_url(Envoy::Config::TestTypeUrl::get().Cluster);
    ASSERT_NE(nullptr, ads_stream_);
    ads_stream_->sendGrpcMessage(response);
  }

  void sendLdsResponse(const std::vector<envoy::config::listener::v3::Listener>& listener_configs,
                       const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_type_url(Envoy::Config::TestTypeUrl::get().Listener);
    for (const auto& listener_config : listener_configs) {
      response.add_resources()->PackFrom(listener_config);
    }
    ASSERT_NE(nullptr, ads_stream_);
    ads_stream_->sendGrpcMessage(response);
  }

  void sendLdsResponse(const std::vector<std::string>& listener_configs,
                       const std::string& version) {
    std::vector<envoy::config::listener::v3::Listener> proto_configs;
    proto_configs.reserve(listener_configs.size());
    for (const auto& listener_blob : listener_configs) {
      proto_configs.emplace_back(
          TestUtility::parseYaml<envoy::config::listener::v3::Listener>(listener_blob));
    }
    sendLdsResponse(proto_configs, version);
  }

  void sendNpdsResponse(const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_type_url(NetworkPolicyTypeUrl);
    std::vector<cilium::NetworkPolicy> proto_configs;
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicy>(policy1));
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicy>(policy2));
    for (const auto& policy_config : proto_configs) {
      response.add_resources()->PackFrom(policy_config);
    }
    ASSERT_NE(nullptr, ads_stream_);
    ads_stream_->sendGrpcMessage(response);
  }

  void sendNphdsResponse(const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_type_url(NetworkPolicyHostsTypeUrl);
    std::vector<cilium::NetworkPolicyHosts> proto_configs;
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicyHosts>(policy_host1));
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicyHosts>(policy_host2));
    for (const auto& policy_host_config : proto_configs) {
      response.add_resources()->PackFrom(policy_host_config);
    }
    ASSERT_NE(nullptr, ads_stream_);
    ads_stream_->sendGrpcMessage(response);
  }

  void resetConnections() {
    if (ads_connection_ != nullptr) {
      AssertionResult result = ads_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = ads_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
      ads_connection_.reset();
    }
  }

  envoy::config::listener::v3::Listener listener_config_;
  std::string listener_name_{"testing-listener-0"};
  FakeHttpConnectionPtr ads_connection_;
  FakeStreamPtr ads_stream_;
};

INSTANTIATE_TEST_SUITE_P(IpVersionsAndGrpcTypes, BpfMetadataIntegrationTest,
                         GRPC_CLIENT_INTEGRATION_PARAMS);

TEST_P(BpfMetadataIntegrationTest, BpfMetadataWithNpdsAndNpdhsViaAds) {
  on_server_init_function_ = [&]() {
    createAdsStream();
    addBpfMetadataListenerFilter(listener_config_, /*use_ads=*/true);
    EXPECT_TRUE(compareDiscoveryRequest(
        Config::TestTypeUrl::get().Cluster, "", {}, {}, {},
        /*expect_node=*/true, Envoy::Grpc::Status::WellKnownGrpcStatus::Ok, "", ads_stream_.get()));
    sendCdsResponse("1");
    EXPECT_TRUE(compareDiscoveryRequest(
        Config::TestTypeUrl::get().Listener, "", {}, {}, {}, /*expect_node=*/false,
        Grpc::Status::WellKnownGrpcStatus::Ok, "", ads_stream_.get()));
    sendLdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
  };
  initialize();

  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
  sendNpdsResponse("1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  sendNphdsResponse("1");
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 1);
}

} // namespace
} // namespace Envoy
