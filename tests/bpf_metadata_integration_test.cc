#include <fmt/format.h>
#include <spdlog/common.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/core/v3/grpc_service.pb.h"
#include "envoy/config/listener/v3/listener.pb.h"
#include "envoy/grpc/status.h"
#include "envoy/http/codec.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/base_logger.h"
#include "source/common/common/logger.h"
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

const std::string invalid_policy = R"EOF(
  endpoint_id: 8192
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
    use_lds_ = false;    // skip built in listener setup, we do it explicitly via xDS
    setUpstreamCount(1); // same as default
    defer_listener_finalization_ = true;

    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }

  ~BpfMetadataIntegrationTest() override { resetConnections(); }

  void setUpGrpcLds(bool use_ads = true) {
    config_helper_.addConfigModifier(
        [this, use_ads](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
          listener_config_.Swap(bootstrap.mutable_static_resources()->mutable_listeners(0));
          listener_config_.set_name(listener_name_);
          bootstrap.mutable_static_resources()->mutable_listeners()->Clear();

          auto* lds_config_source = bootstrap.mutable_dynamic_resources()->mutable_lds_config();
          lds_config_source->Clear();
          lds_config_source->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
          if (use_ads) {
            lds_config_source->mutable_ads();
          } else {
            setGrpcApiConfigSource(*lds_config_source);
          }
        });
  }

  void setGrpcApiConfigSource(envoy::config::core::v3::ConfigSource& config_source,
                              envoy::config::core::v3::ApiConfigSource::ApiType api_type =
                                  envoy::config::core::v3::ApiConfigSource::GRPC) {
    config_source.set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
    auto* api_config_source = config_source.mutable_api_config_source();
    api_config_source->set_set_node_on_first_message_only(true);
    api_config_source->set_api_type(api_type);
    api_config_source->set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
    api_config_source->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
        "xds-grpc-cilium");
  }

  void setBpfMetadataNpdsConfig(::cilium::BpfMetadata& bpf_config, bool use_ads,
                                envoy::config::core::v3::ApiConfigSource::ApiType api_type =
                                    envoy::config::core::v3::ApiConfigSource::GRPC) {
    auto* config_source = bpf_config.mutable_cilium_config_source();
    config_source->Clear();
    if (use_ads) {
      config_source->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
      config_source->mutable_ads();
    } else {
      setGrpcApiConfigSource(*config_source, api_type);
    }
  }

  // Inject the cilium.bpf_metadata listener filter with config_source into the listener.
  void addBpfMetadataListenerFilter(envoy::config::listener::v3::Listener& listener, bool use_ads,
                                    envoy::config::core::v3::ApiConfigSource::ApiType api_type =
                                        envoy::config::core::v3::ApiConfigSource::GRPC) {
    auto* listener_filter = listener.add_listener_filters();
    listener_filter->set_name("cilium.bpf_metadata");

    ::cilium::BpfMetadata bpf_config;
    bpf_config.set_is_ingress(false);
    bpf_config.set_use_nphds(true);

    setBpfMetadataNpdsConfig(bpf_config, use_ads, api_type);

    listener_filter->mutable_typed_config()->PackFrom(bpf_config);
  }

  void initializeAds() {
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

  void initializeSotw() {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* xds_cluster = bootstrap.mutable_static_resources()->add_clusters();
      xds_cluster->MergeFrom(bootstrap.static_resources().clusters()[0]);
      xds_cluster->set_name("xds-grpc-cilium");
      ConfigHelper::setHttp2(*xds_cluster);

      auto* cds_config = bootstrap.mutable_dynamic_resources()->mutable_cds_config();
      setGrpcApiConfigSource(*cds_config);
    });

    // Must be last modifier — it removes static listeners.
    setUpGrpcLds(/*use_ads=*/false);

    BaseIntegrationTest::initialize();
  }

  void createUpstreams() override {
    BaseIntegrationTest::createUpstreams();
    // ADS or SotW upstream (fake_upstreams_[1]).
    addFakeUpstream(Envoy::Http::CodecType::HTTP2);
  }

  FakeUpstream& getFakeUpstream() const { return *fake_upstreams_[1]; }

  void createXdsConnection() {
    if (xds_connection_ == nullptr) {
      AssertionResult result =
          getFakeUpstream().waitForHttpConnection(*dispatcher_, xds_connection_);
      RELEASE_ASSERT(result, result.message());
    }
  }

  void createXdsStream(FakeStreamPtr& stream) {
    auto result = xds_connection_->waitForNewStream(*dispatcher_, stream);
    RELEASE_ASSERT(result, result.message());
    result = stream->waitForHeadersComplete();
    RELEASE_ASSERT(result, result.message());
    stream->startGrpcStream();
  }

  void createAdsStream() {
    createXdsConnection();
    createXdsStream(ads_stream_);
  }

  void createSotWStreams(const std::string& response_version) {
    createXdsConnection();

    // "4" here is just big enough to finally get to the NPDS stream in this loop.
    for (int i = 0; i < 4; i++) {
      FakeStreamPtr stream;
      createXdsStream(stream);

      envoy::service::discovery::v3::DiscoveryRequest request;
      auto result = stream->waitForGrpcMessage(*dispatcher_, request);
      RELEASE_ASSERT(result, result.message());
      if (request.type_url() == NetworkPolicyTypeUrl) {
        ENVOY_LOG_MISC(info, "GOT NPDS STREAM");
        npds_stream_ = std::move(stream);
        return;
      } else if (request.type_url() == Envoy::Config::TestTypeUrl::get().Listener) {
        ENVOY_LOG_MISC(info, "GOT LDS STREAM");
        lds_stream_ = std::move(stream);
        sendLdsResponse(*lds_stream_, {MessageUtil::getYamlStringFromMessage(listener_config_)},
                        response_version);
      } else if (request.type_url() == Envoy::Config::TestTypeUrl::get().Cluster) {
        ENVOY_LOG_MISC(info, "GOT CDS STREAM");
        cds_stream_ = std::move(stream);
        sendCdsResponse(*cds_stream_, response_version);
      } else if (request.type_url() == NetworkPolicyHostsTypeUrl) {
        ENVOY_LOG_MISC(info, "GOT NPHDS STREAM");
        nphds_stream_ = std::move(stream);
        sendNphdsResponse(*nphds_stream_, response_version);
      }
    }

    RELEASE_ASSERT(npds_stream_ != nullptr, "NPDS stream was not established");
  }

  void sendCdsResponse(FakeStream& stream, const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_nonce(version);
    response.set_type_url(Envoy::Config::TestTypeUrl::get().Cluster);
    stream.sendGrpcMessage(response);
  }

  void sendLdsResponse(FakeStream& stream,
                       const std::vector<envoy::config::listener::v3::Listener>& listener_configs,
                       const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_nonce(version);
    response.set_type_url(Envoy::Config::TestTypeUrl::get().Listener);
    for (const auto& listener_config : listener_configs) {
      response.add_resources()->PackFrom(listener_config);
    }
    stream.sendGrpcMessage(response);
  }

  void sendLdsResponse(FakeStream& stream, const std::vector<std::string>& listener_configs,
                       const std::string& version) {
    std::vector<envoy::config::listener::v3::Listener> proto_configs;
    proto_configs.reserve(listener_configs.size());
    for (const auto& listener_blob : listener_configs) {
      proto_configs.emplace_back(
          TestUtility::parseYaml<envoy::config::listener::v3::Listener>(listener_blob));
    }
    sendLdsResponse(stream, proto_configs, version);
  }

  void sendNpdsResponse(FakeStream& stream, const std::string& version,
                        const std::vector<std::string>& policy_configs = {policy1, policy2}) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_nonce(version);
    response.set_type_url(NetworkPolicyTypeUrl);
    std::vector<cilium::NetworkPolicy> proto_configs;
    proto_configs.reserve(policy_configs.size());
    for (const auto& policy_config : policy_configs) {
      proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicy>(policy_config));
    }
    for (const auto& policy_config : proto_configs) {
      response.add_resources()->PackFrom(policy_config);
    }
    stream.sendGrpcMessage(response);
  }

  void sendNphdsResponse(FakeStream& stream, const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_nonce(version);
    response.set_type_url(NetworkPolicyHostsTypeUrl);
    std::vector<cilium::NetworkPolicyHosts> proto_configs;
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicyHosts>(policy_host1));
    proto_configs.emplace_back(TestUtility::parseYaml<cilium::NetworkPolicyHosts>(policy_host2));
    for (const auto& policy_host_config : proto_configs) {
      response.add_resources()->PackFrom(policy_host_config);
    }
    stream.sendGrpcMessage(response);
  }

  void resetConnections() {
    if (xds_connection_ != nullptr) {
      AssertionResult result = xds_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = xds_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
      xds_connection_.reset();
    }
    ads_stream_.reset();
    lds_stream_.reset();
    cds_stream_.reset();
    npds_stream_.reset();
    nphds_stream_.reset();
  }

  uint64_t policyStreamGeneration() const {
    return test_server_->gauge("cilium.policy.policy_stream_generation")->value();
  }

  uint64_t waitForPolicyStreamGenerationAfter(uint64_t previous_generation) {
    test_server_->waitForGaugeGe("cilium.policy.policy_stream_generation", previous_generation + 1);
    const uint64_t generation = policyStreamGeneration();
    EXPECT_GT(generation, previous_generation);
    return generation;
  }

  envoy::config::listener::v3::Listener listener_config_;
  std::string listener_name_{"testing-listener-0"};
  FakeHttpConnectionPtr xds_connection_;
  FakeStreamPtr ads_stream_;
  FakeStreamPtr lds_stream_;
  FakeStreamPtr cds_stream_;
  FakeStreamPtr npds_stream_;
  FakeStreamPtr nphds_stream_;
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
    sendCdsResponse(*ads_stream_, "1");
    EXPECT_TRUE(compareDiscoveryRequest(
        Config::TestTypeUrl::get().Listener, "", {}, {}, {}, /*expect_node=*/false,
        Grpc::Status::WellKnownGrpcStatus::Ok, "", ads_stream_.get()));
    sendLdsResponse(*ads_stream_, {MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
  };
  initializeAds();

  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
  sendNpdsResponse(*ads_stream_, "1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  sendNphdsResponse(*ads_stream_, "1");
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 1);
}

TEST_P(BpfMetadataIntegrationTest, PolicyStreamGenerationTracksAcceptedAdsGrpcStreams) {
  on_server_init_function_ = [&]() {
    createAdsStream();
    addBpfMetadataListenerFilter(listener_config_, /*use_ads=*/true);
    EXPECT_TRUE(compareDiscoveryRequest(
        Config::TestTypeUrl::get().Cluster, "", {}, {}, {},
        /*expect_node=*/true, Envoy::Grpc::Status::WellKnownGrpcStatus::Ok, "", ads_stream_.get()));
    sendCdsResponse(*ads_stream_, "1");
    EXPECT_TRUE(compareDiscoveryRequest(
        Config::TestTypeUrl::get().Listener, "", {}, {}, {}, /*expect_node=*/false,
        Grpc::Status::WellKnownGrpcStatus::Ok, "", ads_stream_.get()));
    sendLdsResponse(*ads_stream_, {MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
  };
  initializeAds();

  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  EXPECT_EQ(policyStreamGeneration(), 0);

  sendNpdsResponse(*ads_stream_, "1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  const uint64_t first_generation = waitForPolicyStreamGenerationAfter(0);

  sendNpdsResponse(*ads_stream_, "2");
  test_server_->waitForCounterGe("cilium.policy.update_success", 2);
  EXPECT_EQ(policyStreamGeneration(), first_generation);

  resetConnections();
  EXPECT_EQ(policyStreamGeneration(), first_generation);
}

TEST_P(BpfMetadataIntegrationTest, PolicyStreamGenerationTracksAcceptedSotwGrpcStreams) {
  on_server_init_function_ = [&]() {
    addBpfMetadataListenerFilter(listener_config_, /*use_ads=*/false);
    createSotWStreams("1");
  };
  initializeSotw();
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  EXPECT_EQ(policyStreamGeneration(), 0);

  sendNpdsResponse(*npds_stream_, "1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  const uint64_t first_generation = waitForPolicyStreamGenerationAfter(0);

  sendNpdsResponse(*npds_stream_, "2");
  test_server_->waitForCounterGe("cilium.policy.update_success", 2);
  EXPECT_EQ(policyStreamGeneration(), first_generation);

  resetConnections();
  EXPECT_EQ(policyStreamGeneration(), first_generation);

  createSotWStreams("2");
  sendNpdsResponse(*npds_stream_, "3", {invalid_policy});
  // The invalid policy is rejected by the real gRPC subscription decoder/validator before
  // NetworkPolicyMapImpl::onConfigUpdate() runs, so this increments NPDS subscription stats
  // rather than cilium.policy.updates_rejected.
  test_server_->waitForCounterGe("cilium.npds.update_rejected", 1);
  EXPECT_EQ(policyStreamGeneration(), first_generation);

  sendNpdsResponse(*npds_stream_, "4");
  test_server_->waitForCounterGe("cilium.policy.update_success", 3);
  waitForPolicyStreamGenerationAfter(first_generation);
}

} // namespace
} // namespace Envoy
