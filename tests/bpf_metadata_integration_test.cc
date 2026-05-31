#include <fmt/format.h>
#include <spdlog/common.h>

#include <cstdint>
#include <memory>
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
#include "source/common/common/logger.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/utility.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/config/utility.h"
#include "test/integration/base_integration_test.h"
#include "test/integration/fake_upstream.h"
#include "test/test_common/resources.h"
#include "test/test_common/utility.h"

#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "cilium/api/bpf_metadata.pb.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/nphds.pb.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "cilium/policy_id.h"
#include "gtest/gtest.h"

namespace Envoy {
namespace {

const std::string NetworkPolicyTypeUrl = "type.googleapis.com/cilium.NetworkPolicy";
const std::string NetworkPolicyHostsTypeUrl = "type.googleapis.com/cilium.NetworkPolicyHosts";

struct NetworkPolicyResourceConfig {
  std::string name;
  std::string version;
  std::string yaml;
};

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

const NetworkPolicyResourceConfig policy_host1_resource = {"111", "1", R"EOF(
  policy: 111
  host_addresses: [ "10.1.1.1", "f00d::1:1:1" ]
)EOF"};

const NetworkPolicyResourceConfig policy_host2_resource = {"222", "1", R"EOF(
  policy: 222
  host_addresses: [ "10.2.2.2", "f00d::2:2:2" ]
)EOF"};

const NetworkPolicyResourceConfig policy_host1_new_stream_resource = {"111", "2", R"EOF(
  policy: 111
  host_addresses: [ "10.1.1.1", "f00d::1:1:1" ]
)EOF"};

const NetworkPolicyResourceConfig policy42_resource = {"policy-42", "1", R"EOF(
  endpoint_ips:
  - '10.1.2.3'
  endpoint_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 222 ]
)EOF"};

const NetworkPolicyResourceConfig policy43_resource = {"policy-43", "1", R"EOF(
  endpoint_ips:
  - '10.2.3.4'
  endpoint_id: 43
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 111 ]
)EOF"};

const NetworkPolicyResourceConfig policy42_new_stream_resource = {"policy-42", "2", R"EOF(
  endpoint_ips:
  - '10.1.2.3'
  endpoint_id: 42
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 222 ]
)EOF"};

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

#if 0
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
#endif
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

  void updateBpfMetadataListenerFilter(envoy::config::listener::v3::Listener& listener,
                                       envoy::config::core::v3::ApiConfigSource::ApiType api_type) {
    for (auto& listener_filter : *listener.mutable_listener_filters()) {
      if (listener_filter.name() != "cilium.bpf_metadata") {
        continue;
      }

      ::cilium::BpfMetadata bpf_config;
      RELEASE_ASSERT(listener_filter.typed_config().UnpackTo(&bpf_config),
                     "failed to unpack cilium.bpf_metadata listener filter");
      setBpfMetadataNpdsConfig(bpf_config, /*use_ads=*/false, api_type);
      listener_filter.mutable_typed_config()->PackFrom(bpf_config);
      return;
    }
    RELEASE_ASSERT(false, "cilium.bpf_metadata listener filter not found");
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

  void createStreamsUntil(const std::string& response_version, absl::string_view type_url,
                          bool expect_delta = false) {
    createXdsConnection();

    // "4" here is just big enough to finally get to the NPDS stream in this loop.
    for (int i = 0; i < 4; i++) {
      FakeStreamPtr stream;
      createXdsStream(stream);

      std::string request_type_url;
      const bool is_delta =
          stream->headers().getPathValue().find("/Delta") != absl::string_view::npos;
      if (is_delta) {
        envoy::service::discovery::v3::DeltaDiscoveryRequest request;
        auto result = stream->waitForGrpcMessage(*dispatcher_, request);
        RELEASE_ASSERT(result, result.message());
        request_type_url = request.type_url();
      } else {
        envoy::service::discovery::v3::DiscoveryRequest request;
        auto result = stream->waitForGrpcMessage(*dispatcher_, request);
        RELEASE_ASSERT(result, result.message());
        request_type_url = request.type_url();
      }

      if (request_type_url == NetworkPolicyTypeUrl) {
        ENVOY_LOG_MISC(info, "GOT NPDS STREAM");
        npds_stream_ = std::move(stream);
        if (type_url == NetworkPolicyTypeUrl && is_delta == expect_delta) {
          return;
        }
      } else if (request_type_url == Envoy::Config::TestTypeUrl::get().Listener) {
        ENVOY_LOG_MISC(info, "GOT LDS STREAM");
        lds_stream_ = std::move(stream);
        sendLdsResponse(*lds_stream_, {MessageUtil::getYamlStringFromMessage(listener_config_)},
                        response_version);
      } else if (request_type_url == Envoy::Config::TestTypeUrl::get().Cluster) {
        ENVOY_LOG_MISC(info, "GOT CDS STREAM");
        cds_stream_ = std::move(stream);
        sendCdsResponse(*cds_stream_, response_version);
      } else if (request_type_url == NetworkPolicyHostsTypeUrl) {
        ENVOY_LOG_MISC(info, "GOT NPHDS STREAM");
        nphds_stream_ = std::move(stream);
        if (!is_delta) {
          sendNphdsResponse(*nphds_stream_, response_version);
        }
        if (type_url == NetworkPolicyHostsTypeUrl && is_delta == expect_delta) {
          return;
        }
      }
    }

    RELEASE_ASSERT(false, fmt::format("{} stream was not established", type_url));
  }

  void createSotWStreams(const std::string& response_version) {
    createStreamsUntil(response_version, NetworkPolicyTypeUrl);
    if (nphds_stream_ == nullptr) {
      createStreamsUntil(response_version, NetworkPolicyHostsTypeUrl);
    }
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

  void sendNpdsDeltaResponse(FakeStream& stream, const std::string& version,
                             const std::vector<NetworkPolicyResourceConfig>& resource_configs,
                             const std::vector<std::string>& removed_resources = {}) {
    envoy::service::discovery::v3::DeltaDiscoveryResponse response;
    response.set_system_version_info(version);
    response.set_nonce(version);
    response.set_type_url(NetworkPolicyTypeUrl);
    for (const auto& resource_config : resource_configs) {
      envoy::service::discovery::v3::Resource* resource = response.add_resources();
      resource->set_name(resource_config.name);
      resource->set_version(resource_config.version);
      resource->mutable_resource()->PackFrom(
          TestUtility::parseYaml<cilium::NetworkPolicy>(resource_config.yaml));
    }
    for (const auto& removed_resource : removed_resources) {
      response.add_removed_resources(removed_resource);
    }
    stream.sendGrpcMessage(response);
  }

  void sendNphdsDeltaResponse(FakeStream& stream, const std::string& version,
                              const std::vector<NetworkPolicyResourceConfig>& resource_configs,
                              const std::vector<std::string>& removed_resources = {}) {
    envoy::service::discovery::v3::DeltaDiscoveryResponse response;
    response.set_system_version_info(version);
    response.set_nonce(version);
    response.set_type_url(NetworkPolicyHostsTypeUrl);
    for (const auto& resource_config : resource_configs) {
      envoy::service::discovery::v3::Resource* resource = response.add_resources();
      resource->set_name(resource_config.name);
      resource->set_version(resource_config.version);
      resource->mutable_resource()->PackFrom(
          TestUtility::parseYaml<cilium::NetworkPolicyHosts>(resource_config.yaml));
    }
    for (const auto& removed_resource : removed_resources) {
      response.add_removed_resources(removed_resource);
    }
    stream.sendGrpcMessage(response);
  }

  AssertionResult compareNpdsAck() {
    return compareDeltaDiscoveryRequest(NetworkPolicyTypeUrl, {}, {}, npds_stream_.get(),
                                        Grpc::Status::WellKnownGrpcStatus::Ok, "",
                                        /*expect_node=*/false);
  }

  AssertionResult compareNphdsAck() {
    return compareDeltaDiscoveryRequest(NetworkPolicyHostsTypeUrl, {}, {}, nphds_stream_.get(),
                                        Grpc::Status::WellKnownGrpcStatus::Ok, "",
                                        /*expect_node=*/false);
  }

  void retireStream(FakeStreamPtr& stream) {
    if (stream != nullptr) {
      retired_streams_.push_back(std::move(stream));
    }
  }

  void resetGrpcStream(FakeStreamPtr& stream) {
    stream->encodeResetStream();
    AssertionResult result = stream->waitForReset(*dispatcher_);
    RELEASE_ASSERT(result, result.message());
    retireStream(stream);
  }

  void resetNpdsStream() { resetGrpcStream(npds_stream_); }

  void resetNphdsStream() { resetGrpcStream(nphds_stream_); }

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

  std::shared_ptr<const Cilium::NetworkPolicyMap> networkPolicyMap() const {
    auto map = test_server_->server().singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
        "cilium_network_policy_singleton");
    RELEASE_ASSERT(map != nullptr, "Cilium NetworkPolicyMap singleton was not created");
    return map;
  }

  uint64_t resolveHostPolicyId(const std::string& address) const {
    auto parsed_address = Network::Utility::parseInternetAddressNoThrow(address);
    RELEASE_ASSERT(parsed_address != nullptr,
                   fmt::format("failed to parse host address {}", address));
    auto map = test_server_->server().singletonManager().getTyped<const Cilium::PolicyHostMap>(
        "cilium_host_map_singleton");
    RELEASE_ASSERT(map != nullptr, "Cilium PolicyHostMap singleton was not created");

    absl::Mutex lock;
    bool resolved = false;
    uint64_t policy_id = Cilium::ID::UNKNOWN;

    // PolicyHostMap lookups must run on an Envoy thread that has thread-local storage registered.
    // The gtest/integration thread calling this helper is not such a thread, so dereferencing the
    // TLS-backed host map directly here is unsafe. Posting the resolve to the server dispatcher
    // keeps the lookup on a valid Envoy TLS thread while still letting the test read the result.
    test_server_->server().dispatcher().post([&, map, parsed_address]() {
      policy_id = map->resolve(parsed_address->ip());
      lock.Lock();
      resolved = true;
      lock.Unlock();
    });

    lock.LockWhen(absl::Condition(&resolved));
    lock.Unlock();
    return policy_id;
  }

  envoy::config::listener::v3::Listener listener_config_;
  std::string listener_name_{"testing-listener-0"};
  FakeHttpConnectionPtr xds_connection_;
  FakeStreamPtr ads_stream_;
  FakeStreamPtr lds_stream_;
  FakeStreamPtr cds_stream_;
  FakeStreamPtr npds_stream_;
  FakeStreamPtr nphds_stream_;
  std::vector<FakeStreamPtr> retired_streams_;
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

TEST_P(BpfMetadataIntegrationTest, PolicyStreamGenerationTracksAcceptedDeltaNpdsStreams) {
  on_server_init_function_ = [&]() {
    // Step 1: establish the initial SotW LDS, CDS, NPHDS, and NPDS streams.
    addBpfMetadataListenerFilter(listener_config_, /*use_ads=*/false);
    createSotWStreams("1");
  };
  initializeSotw();
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);

  auto policy_map = networkPolicyMap();
  EXPECT_EQ(policyStreamGeneration(), 0);

  // Step 2: accept a real SotW NPDS response so the starting mode has installed policy.
  sendNpdsResponse(*npds_stream_, "1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  const uint64_t sotw_generation = waitForPolicyStreamGenerationAfter(0);
  EXPECT_TRUE(policy_map->exists("10.1.1.1"));
  EXPECT_TRUE(policy_map->exists("10.2.2.2"));

  // Step 3: update the BpfMetadata config source; this is evidence that Delta NPDS is available.
  updateBpfMetadataListenerFilter(listener_config_,
                                  envoy::config::core::v3::ApiConfigSource::DELTA_GRPC);
  sendLdsResponse(*lds_stream_, {listener_config_}, "2");
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 2);

  // Step 4: observe the immediate switch to Delta NPDS without advancing accepted policy state.
  createStreamsUntil("2", NetworkPolicyTypeUrl, /*expect_delta=*/true);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);

  // Step 5: accept the first Delta NPDS update and retire the prior SotW policy resources.
  sendNpdsDeltaResponse(*npds_stream_, "1", {policy42_resource, policy43_resource});
  EXPECT_TRUE(compareNpdsAck());
  const uint64_t first_generation = waitForPolicyStreamGenerationAfter(sotw_generation);
  EXPECT_FALSE(policy_map->exists("10.1.1.1"));
  EXPECT_FALSE(policy_map->exists("10.2.2.2"));
  EXPECT_TRUE(policy_map->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map->exists("10.2.3.4"));

  // Step 6: accept a same-stream Delta update; stream generation and omitted resources stay put.
  sendNpdsDeltaResponse(*npds_stream_, "2", {policy42_new_stream_resource});
  EXPECT_TRUE(compareNpdsAck());
  EXPECT_EQ(policyStreamGeneration(), first_generation);
  EXPECT_TRUE(policy_map->exists("10.1.2.3"));
  EXPECT_TRUE(policy_map->exists("10.2.3.4"));

  // Step 7: reset the Delta NPDS stream.
  resetNpdsStream();

  // Step 8: open the replacement Delta stream; reconnect alone must not advance policy state.
  createStreamsUntil("3", NetworkPolicyTypeUrl, /*expect_delta=*/true);
  EXPECT_EQ(policyStreamGeneration(), first_generation);
  EXPECT_TRUE(policy_map->exists("10.2.3.4"));

  // Step 9: accept the first update on the new stream and retire resources from the old stream.
  sendNpdsDeltaResponse(*npds_stream_, "3", {policy42_new_stream_resource});
  waitForPolicyStreamGenerationAfter(first_generation);
  EXPECT_TRUE(policy_map->exists("10.1.2.3"));
  EXPECT_FALSE(policy_map->exists("10.2.3.4"));
}

TEST_P(BpfMetadataIntegrationTest, PolicyStreamGenerationTracksAcceptedDeltaNphdsStreams) {
  on_server_init_function_ = [&]() {
    // Step 1: establish the initial SotW LDS, CDS, NPHDS, and NPDS streams.
    addBpfMetadataListenerFilter(listener_config_, /*use_ads=*/false);
    createSotWStreams("1");
  };
  initializeSotw();
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 1);

  auto policy_map = networkPolicyMap();
  EXPECT_EQ(policyStreamGeneration(), 0);
  EXPECT_EQ(resolveHostPolicyId("10.1.1.1"), 111);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), 222);

  // Step 2: accept a real SotW NPDS response so the starting mode has installed policy.
  sendNpdsResponse(*npds_stream_, "1");
  test_server_->waitForCounterGe("cilium.policy.update_success", 1);
  const uint64_t sotw_generation = waitForPolicyStreamGenerationAfter(0);
  EXPECT_TRUE(policy_map->exists("10.1.1.1"));
  EXPECT_TRUE(policy_map->exists("10.2.2.2"));

  // Step 3: update the BpfMetadata config source; this is evidence that Delta NPHDS is available.
  updateBpfMetadataListenerFilter(listener_config_,
                                  envoy::config::core::v3::ApiConfigSource::DELTA_GRPC);
  sendLdsResponse(*lds_stream_, {listener_config_}, "2");
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 2);

  // Step 4: observe the immediate switch to Delta NPHDS without advancing accepted policy state.
  createStreamsUntil("2", NetworkPolicyHostsTypeUrl, /*expect_delta=*/true);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);
  EXPECT_EQ(resolveHostPolicyId("10.1.1.1"), 111);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), 222);

  // Step 5: accept the first Delta NPHDS update. This should not change policy stream generation.
  sendNphdsDeltaResponse(*nphds_stream_, "1", {policy_host1_resource, policy_host2_resource});
  EXPECT_TRUE(compareNphdsAck());
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 2);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);
  EXPECT_EQ(resolveHostPolicyId("10.1.1.1"), 111);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), 222);

  // Step 6: accept a same-stream Delta update; omitted resources stay present on the same stream.
  sendNphdsDeltaResponse(*nphds_stream_, "2", {policy_host1_new_stream_resource});
  EXPECT_TRUE(compareNphdsAck());
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 3);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);
  EXPECT_EQ(resolveHostPolicyId("10.1.1.1"), 111);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), 222);

  // Step 7: reset the Delta NPHDS stream.
  resetNphdsStream();

  // Step 8: open the replacement Delta stream; reconnect alone must not advance policy state.
  createStreamsUntil("3", NetworkPolicyHostsTypeUrl, /*expect_delta=*/true);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), 222);

  // Step 9: accept the first update on the new stream and retire resources from the old stream.
  sendNphdsDeltaResponse(*nphds_stream_, "3", {policy_host1_new_stream_resource});
  EXPECT_TRUE(compareNphdsAck());
  test_server_->waitForCounterGe("cilium.hostmap.update_success", 4);
  EXPECT_EQ(policyStreamGeneration(), sotw_generation);
  EXPECT_EQ(resolveHostPolicyId("10.1.1.1"), 111);
  EXPECT_EQ(resolveHostPolicyId("10.2.2.2"), Cilium::ID::UNKNOWN);
}

} // namespace
} // namespace Envoy
