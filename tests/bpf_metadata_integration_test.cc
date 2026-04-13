#include <fmt/format.h>
#include <gtest/gtest-param-test.h>
#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "cilium/api/bpf_metadata.pb.h"
#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/listener/v3/listener.pb.h"
#include "envoy/network/address.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"

#include "test/common/grpc/grpc_client_integration.h"
#include "test/integration/base_integration_test.h"
#include "test/integration/fake_upstream.h"
#include "test/integration/integration_tcp_client.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"
#include "test/test_common/resources.h"
#include "test/test_common/utility.h"

#include "cilium/api/npds.pb.h"

namespace Envoy {
namespace Cilium {
namespace BpfMetadata {

// Network policy that allows all traffic on the upstream port for both ingress and egress.
const std::string BPF_METADATA_POLICY_fmt = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  endpoint_ips:
  - '{{ ntop_ip_loopback_address }}'
  endpoint_id: 3
  ingress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
  egress_per_port_policies:
  - port: {0}
    rules:
    - remote_policies: [ 1 ]
)EOF";

// Envoy config with bpf_metadata listener filter and tcp_proxy.
// params: is_ingress ("true", "false")
const std::string bpf_metadata_tcp_config_fmt = R"EOF(
admin:
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: cluster1
    type: ORIGINAL_DST
    lb_policy: CLUSTER_PROVIDED
    connect_timeout:
      seconds: 1
  - name: xds-grpc-cilium
    connect_timeout:
      seconds: 5
    type: STATIC
    lb_policy: ROUND_ROBIN
    http2_protocol_options:
    load_assignment:
      cluster_name: xds-grpc-cilium
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              pipe:
                path: /var/run/cilium/xds.sock
  - name: xds-grpc-cilium-custom
    connect_timeout:
      seconds: 5
    type: STATIC
    lb_policy: ROUND_ROBIN
    http2_protocol_options:
    load_assignment:
      cluster_name: xds-grpc-cilium-custom
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              pipe:
                path: /var/run/cilium/xds.sock
  listeners:
    name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    listener_filters:
      name: bpf_metadata
      typed_config:
        "@type": type.googleapis.com/cilium.BpfMetadata
        is_ingress: {0}
        npds_config:
            api_config_source:
              api_type: GRPC
              grpc_services:
                envoy_grpc:
                  cluster_name: "xds-grpc-cilium-custom"
    filter_chains:
      filters:
      - name: cilium.network
        typed_config:
          "@type": type.googleapis.com/cilium.NetworkFilter
      - name: envoy.tcp_proxy
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class BpfMetadataXdsIntegrationTest : public BaseIntegrationTest,
                                      public Grpc::GrpcClientIntegrationParamTest {
public:
  BpfMetadataXdsIntegrationTest()
      : BaseIntegrationTest(ipVersion(), ConfigHelper::baseConfig()) {
    enableHalfClose(true);
    skip_tag_extraction_rule_check_ = true;
  }

  ~BpfMetadataXdsIntegrationTest() override { resetConnections(); }

  std::string testPolicyFmt() {
    return TestEnvironment::substitute(BPF_METADATA_POLICY_fmt, ipVersion());
  }

  void createEnvoy() override {
    BaseIntegrationTest::createEnvoy();
  }

  void setUpGrpcXds() {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      // Extract listener config to be sent via LDS later.
      listener_config_.Swap(bootstrap.mutable_static_resources()->mutable_listeners(0));
      listener_config_.set_name(listener_name_);
      bootstrap.mutable_static_resources()->mutable_listeners()->Clear();

      // Set up LDS config source pointing to our fake gRPC upstream.
      auto* lds_config_source =
          bootstrap.mutable_dynamic_resources()->mutable_lds_config();
      lds_config_source->set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
      auto* lds_api_config_source =
          lds_config_source->mutable_api_config_source();
      lds_api_config_source->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
      lds_api_config_source->set_transport_api_version(envoy::config::core::v3::V3);
      envoy::config::core::v3::GrpcService* grpc_service =
          lds_api_config_source->add_grpc_services();
      setGrpcService(*grpc_service, "xds-grpc-cilium-custom",
                     getXdsFakeUpstream().localAddress());
    });
  }

  void initialize() override {
    use_lds_ = false;
    setUpstreamCount(2);
    defer_listener_finalization_ = true;

    // Build the bootstrap config programmatically instead of using YAML.
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      auto* static_resources = bootstrap.mutable_static_resources();

    // Add xds-grpc-cilium cluster (pipe to /var/run/cilium/xds.sock).
    auto* xds_cluster = static_resources->add_clusters();
    xds_cluster->set_name("xds-grpc-cilium-custom");
    xds_cluster->mutable_connect_timeout()->set_seconds(5);
    xds_cluster->set_lb_policy(envoy::config::cluster::v3::Cluster::ROUND_ROBIN);
    ConfigHelper::setHttp2(*xds_cluster);

    // Replace cluster_0 with an ORIGINAL_DST cluster named "cluster1".
    auto* cluster1 = static_resources->mutable_clusters(0);
    cluster1->set_name("cluster1");
    cluster1->set_type(envoy::config::cluster::v3::Cluster::ORIGINAL_DST);
    cluster1->set_lb_policy(envoy::config::cluster::v3::Cluster::CLUSTER_PROVIDED);
    cluster1->mutable_connect_timeout()->set_seconds(1);
    cluster1->mutable_load_assignment()->Clear();
    cluster1->clear_typed_extension_protocol_options();
    auto* load_assignment = cluster1->mutable_load_assignment();
    load_assignment->set_cluster_name(cluster1->name());
    auto* endpoints = load_assignment->add_endpoints();
    auto* lb_endpoint = endpoints->add_lb_endpoints();
    auto* endpoint = lb_endpoint->mutable_endpoint();
    auto* address = endpoint->mutable_address()->mutable_socket_address();
    address->set_address(Network::Test::getLoopbackAddressString(ipVersion()));
    address->set_port_value(fake_upstreams_[1]->localAddress()->ip()->port());


    // Configure the listener with bpf_metadata listener filter + cilium.network + tcp_proxy.
    auto* listener = static_resources->mutable_listeners(0);
    listener->set_name(listener_name_);

    // Add bpf_metadata listener filter.
    auto* listener_filter = listener->add_listener_filters();
    listener_filter->set_name("bpf_metadata");
    auto* socket_address = listener->mutable_address()->mutable_socket_address();
    socket_address->set_address(Network::Test::getLoopbackAddressString(version_));
    socket_address->set_port_value(0);
    cilium::BpfMetadata bpf_config;
    bpf_config.set_is_ingress(true);
    auto* npds_config = bpf_config.mutable_npds_config();
    auto* npds_api = npds_config->mutable_api_config_source();
    npds_api->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
    npds_api->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name(
        "xds-grpc-cilium-custom");
    listener_filter->mutable_typed_config()->PackFrom(bpf_config);

      // // Add filter chain with cilium.network + tcp_proxy.
      // auto* filter_chain = listener->add_filter_chains();

      // auto* cilium_filter = filter_chain->add_filters();
      // cilium_filter->set_name("cilium.network");
      // ::cilium::NetworkFilter network_filter_config;
      // cilium_filter->mutable_typed_config()->PackFrom(network_filter_config);

      // auto* tcp_proxy_filter = filter_chain->add_filters();
      // tcp_proxy_filter->set_name("envoy.tcp_proxy");
      // envoy::extensions::filters::network::tcp_proxy::v3::TcpProxy tcp_proxy_config;
      // tcp_proxy_config.set_stat_prefix("tcp_stats");
      // tcp_proxy_config.set_cluster("cluster1");
      // tcp_proxy_filter->mutable_typed_config()->PackFrom(tcp_proxy_config);
    });

    // Note: this must be the last modifier as it nukes static_resource listeners.
    setUpGrpcXds();

    BaseIntegrationTest::initialize();
  }

  void createUpstreams() override {
    BaseIntegrationTest::createUpstreams();
    // Create the NPDS upstream (fake_upstreams_[1]).
    addFakeUpstream(Http::CodecType::HTTP2);
    addFakeUpstream(Http::CodecType::HTTP2);
  }

  FakeUpstream& getXdsFakeUpstream() const { return *fake_upstreams_[0]; }

  void createXdsStream() {
    AssertionResult result =
        getXdsFakeUpstream().waitForHttpConnection(*dispatcher_, npds_connection_);
    RELEASE_ASSERT(result, result.message());
    result = npds_connection_->waitForNewStream(*dispatcher_, npds_stream_);
    RELEASE_ASSERT(result, result.message());
    npds_stream_->startGrpcStream();
  }

  void sendXdsResponse(
      const std::vector<envoy::config::listener::v3::Listener>& listener_configs,
      const std::string& version) {
    envoy::service::discovery::v3::DiscoveryResponse response;
    response.set_version_info(version);
    response.set_type_url(Config::TestTypeUrl::get().Listener);
    for (const auto& listener_config : listener_configs) {
      response.add_resources()->PackFrom(listener_config);
    }
    ASSERT_NE(nullptr, npds_stream_);
    npds_stream_->sendGrpcMessage(response);
  }

  void sendXdsResponse(const std::vector<std::string>& listener_configs,
                        const std::string& version) {
    std::vector<envoy::config::listener::v3::Listener> proto_configs;
    proto_configs.reserve(listener_configs.size());
    for (const auto& listener_blob : listener_configs) {
      proto_configs.emplace_back(
          TestUtility::parseYaml<envoy::config::listener::v3::Listener>(listener_blob));
    }
    sendXdsResponse(proto_configs, version);
  }

  void resetConnections() {
    if (xds_connection_ != nullptr) {
      AssertionResult result = xds_connection_->close();
      RELEASE_ASSERT(result, result.message());
      result = xds_connection_->waitForDisconnect();
      RELEASE_ASSERT(result, result.message());
      xds_connection_.reset();
    }
  }

  envoy::config::listener::v3::Listener listener_config_;
  std::string listener_name_{"listener_0"};
  FakeHttpConnectionPtr npds_connection_;
  FakeStreamPtr npds_stream_{};
};

INSTANTIATE_TEST_SUITE_P(IpVersionsAndGrpcTypes, BpfMetadataXdsIntegrationTest,
                         GRPC_CLIENT_INTEGRATION_PARAMS);

// Tests that a listener added via LDS/NPDS xDS stream successfully proxies
// bidirectional TCP traffic with bpf_metadata.
TEST_P(BpfMetadataXdsIntegrationTest, BasicSuccessWithXds) {
  on_server_init_function_ = [&]() {
    createXdsStream();
    sendXdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
  };
  initialize();
  test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
  test_server_->waitUntilListenersReady();
  test_server_->waitForCounterGe("listener_manager.listener_create_success", 1);
  EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
  registerTestServerPorts({listener_name_});

  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("hello"));
  tcp_client->waitForData("hello");

  ASSERT_TRUE(tcp_client->write("world"));
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(tcp_client->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

// // Tests that removing the listener via xDS is handled cleanly.
// TEST_P(BpfMetadataXdsIntegrationTest, RemoveListener) {
//   on_server_init_function_ = [&]() {
//     createNpdsStream();
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
//   };
//   initialize();
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
//   test_server_->waitUntilListenersReady();
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 1);
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
//   registerTestServerPorts({listener_name_});

//   // Verify traffic works before removal.
//   IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
//   FakeRawConnectionPtr fake_upstream_connection;
//   ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

//   ASSERT_TRUE(fake_upstream_connection->write("hello"));
//   tcp_client->waitForData("hello");
//   ASSERT_TRUE(tcp_client->write("", true));
//   ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
//   ASSERT_TRUE(fake_upstream_connection->write("", true));
//   ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

//   // Remove the listener by sending an empty LDS response.
//   sendNpdsResponse(std::vector<std::string>{}, "2");
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 2);
//   test_server_->waitForGaugeEq("listener_manager.total_listeners_active", 0);
// }

// // Tests that updating the listener via xDS (in-place filter chain update) works.
// TEST_P(BpfMetadataXdsIntegrationTest, UpdateListenerInPlace) {
//   on_server_init_function_ = [&]() {
//     createNpdsStream();
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
//   };
//   initialize();
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
//   test_server_->waitUntilListenersReady();
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 1);
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
//   registerTestServerPorts({listener_name_});

//   // Verify initial traffic works.
//   {
//     IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
//     FakeRawConnectionPtr fake_upstream_connection;
//     ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

//     ASSERT_TRUE(fake_upstream_connection->write("hello"));
//     tcp_client->waitForData("hello");
//     ASSERT_TRUE(tcp_client->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
//     ASSERT_TRUE(fake_upstream_connection->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
//   }

//   // Trigger an in-place update by modifying the filter chain.
//   listener_config_.mutable_filter_chains(0)->mutable_filters(0)->set_name("cilium.network");
//   sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "2");
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 2);

//   // Verify traffic still works after in-place update.
//   registerTestServerPorts({listener_name_});
//   {
//     IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
//     FakeRawConnectionPtr fake_upstream_connection;
//     ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

//     ASSERT_TRUE(fake_upstream_connection->write("world"));
//     tcp_client->waitForData("world");
//     ASSERT_TRUE(tcp_client->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
//     ASSERT_TRUE(fake_upstream_connection->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
//   }
// }

// // Tests that multiple LDS updates work correctly, similar to the Envoy
// // MultipleLdsUpdatesSharingListenSocketFactory test.
// TEST_P(BpfMetadataXdsIntegrationTest, MultipleLdsUpdates) {
//   on_server_init_function_ = [&]() {
//     createNpdsStream();
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
//   };
//   initialize();
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
//   test_server_->waitUntilListenersReady();
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 1);
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
//   registerTestServerPorts({listener_name_});

//   // Make a connection to the listener from version 1.
//   IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
//   FakeRawConnectionPtr fake_upstream_connection;
//   ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));
//   ASSERT_TRUE(fake_upstream_connection->write("v1"));
//   tcp_client->waitForData("v1");
//   ASSERT_TRUE(tcp_client->write("", true));
//   ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
//   ASSERT_TRUE(fake_upstream_connection->write("", true));
//   ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

//   for (int version = 2; version <= 5; version++) {
//     // Touch the metadata to get a different hash.
//     (*(*listener_config_.mutable_metadata()->mutable_filter_metadata())["random_filter_name"]
//           .mutable_fields())["random_key"]
//         .set_number_value(version);
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)},
//                      absl::StrCat(version));
//     test_server_->waitForCounterGe("listener_manager.listener_create_success", version);

//     // Re-register ports since the listener may have been recreated.
//     registerTestServerPorts({listener_name_});

//     IntegrationTcpClientPtr tcp_client2 = makeTcpConnection(lookupPort(listener_name_));
//     FakeRawConnectionPtr fake_upstream_connection2;
//     ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection2));
//     std::string msg = absl::StrCat("v", version);
//     ASSERT_TRUE(fake_upstream_connection2->write(msg));
//     tcp_client2->waitForData(msg);
//     ASSERT_TRUE(tcp_client2->write("", true));
//     ASSERT_TRUE(fake_upstream_connection2->waitForHalfClose());
//     ASSERT_TRUE(fake_upstream_connection2->write("", true));
//     ASSERT_TRUE(fake_upstream_connection2->waitForDisconnect());
//   }
// }

// // Tests that removing a listener before it is fully drained works properly,
// // similar to the Envoy RemoveListenerAfterInPlaceUpdate test.
// TEST_P(BpfMetadataXdsIntegrationTest, RemoveListenerAfterInPlaceUpdate) {
//   on_server_init_function_ = [&]() {
//     createNpdsStream();
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
//   };
//   setDrainTime(std::chrono::seconds(30));
//   initialize();
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
//   test_server_->waitUntilListenersReady();
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 1);
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);
//   registerTestServerPorts({listener_name_});

//   // Trigger a listener in-place update.
//   listener_config_.mutable_filter_chains(0)->mutable_filters(0)->set_name("cilium.network");
//   sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "2");
//   test_server_->waitForCounterGe("listener_manager.listener_create_success", 2);
//   test_server_->waitForCounterEq("listener_manager.listener_in_place_updated", 1);
//   test_server_->waitForGaugeEq("listener_manager.total_filter_chains_draining", 1);

//   // Verify traffic still works on the updated listener.
//   registerTestServerPorts({listener_name_});
//   {
//     IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort(listener_name_));
//     FakeRawConnectionPtr fake_upstream_connection;
//     ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

//     ASSERT_TRUE(fake_upstream_connection->write("hello"));
//     tcp_client->waitForData("hello");
//     ASSERT_TRUE(tcp_client->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
//     ASSERT_TRUE(fake_upstream_connection->write("", true));
//     ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
//   }

//   // Remove the active listener.
//   sendNpdsResponse(std::vector<std::string>{}, "3");
//   test_server_->waitForGaugeEq("listener_manager.total_listeners_active", 0);
//   test_server_->waitForGaugeEq("listener_manager.total_filter_chains_draining", 1);
// }

// // Tests that removing the last uninitialized listener does not block server startup.
// TEST_P(BpfMetadataXdsIntegrationTest, RemoveLastUninitializedListener) {
//   on_server_init_function_ = [&]() {
//     createNpdsStream();
//     sendNpdsResponse({MessageUtil::getYamlStringFromMessage(listener_config_)}, "1");
//   };
//   initialize();
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 1);
//   // listener_0 is added but may not yet be fully initialized.
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 1);

//   // Delete the only listener.
//   sendNpdsResponse(std::vector<std::string>{}, "2");
//   test_server_->waitForCounterGe("listener_manager.lds.update_success", 2);
//   EXPECT_EQ(test_server_->server().listenerManager().listeners().size(), 0);
//   // Server instance should be ready since the listener's destruction marked it initialized.
//   EXPECT_EQ(test_server_->server().initManager().state(), Init::Manager::State::Initialized);
// }

} // namespace BpfMetadata
} // namespace Cilium
} // namespace Envoy
