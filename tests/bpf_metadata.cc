#include "tests/bpf_metadata.h"

#include "source/common/common/logger.h"
#include "source/common/config/filesystem_subscription_impl.h"
#include "source/common/config/utility.h"

#include "test/test_common/environment.h"

#include "cilium/socket_option.h"
#include "tests/bpf_metadata.pb.validate.h"

namespace Envoy {

std::string host_map_config;
std::shared_ptr<const Cilium::PolicyHostMap> hostmap{nullptr}; // Keep reference to singleton

Network::Address::InstanceConstSharedPtr original_dst_address;
std::shared_ptr<const Cilium::NetworkPolicyMap> npmap{nullptr}; // Keep reference to singleton

std::string policy_config;

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(const std::string& config, Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
      "cilium_host_map_singleton", [&config, &context] {
        std::string path = TestEnvironment::writeStringToFileForTest("host_map.yaml", config);
        ENVOY_LOG_MISC(debug, "Loading Cilium Host Map from file \'{}\' instead of using gRPC",
                       path);

        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path, context.api());
        Envoy::Config::SubscriptionStats stats =
            Envoy::Config::Utility::generateStats(context.scope());
        auto map = std::make_shared<Cilium::PolicyHostMap>(context.threadLocal());
        auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl>(
            context.mainThreadDispatcher(), Envoy::Config::makePathConfigSource(path), *map,
            map->shared_from_this(), stats, ProtobufMessage::getNullValidationVisitor(),
            context.api());
        map->startSubscription(std::move(subscription));
        return map;
      });
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(const std::string& config, Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      "cilium_network_policy_singleton", [&config, &context] {
        // File subscription.
        std::string path = TestEnvironment::writeStringToFileForTest("network_policy.yaml", config);
        ENVOY_LOG_MISC(debug,
                       "Loading Cilium Network Policy from file \'{}\' instead "
                       "of using gRPC",
                       path);
        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path, context.api());
        Envoy::Config::SubscriptionStats stats =
            Envoy::Config::Utility::generateStats(context.scope());
        auto map = std::make_shared<Cilium::NetworkPolicyMap>(context);
        auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl>(
            context.mainThreadDispatcher(), Envoy::Config::makePathConfigSource(path), *map,
            map->shared_from_this(), stats, ProtobufMessage::getNullValidationVisitor(),
            context.api());
        map->startSubscription(std::move(subscription));
        return map;
      });
}

} // namespace

void initTestMaps(Server::Configuration::ListenerFactoryContext& context) {
  // Create the file-based policy map before the filter is created, so that the
  // singleton is set before the gRPC subscription is attempted.
  hostmap = createHostMap(host_map_config, context);
  // Create the file-based policy map before the filter is created, so that the
  // singleton is set before the gRPC subscription is attempted.
  npmap = createPolicyMap(policy_config, context);
}

namespace Cilium {
namespace BpfMetadata {

namespace {
::cilium::BpfMetadata getTestConfig(const ::cilium::TestBpfMetadata& config) {
  ::cilium::BpfMetadata test_config;
  test_config.set_is_ingress(config.is_ingress());
  return test_config;
}
} // namespace

TestConfig::TestConfig(const ::cilium::TestBpfMetadata& config,
                       Server::Configuration::ListenerFactoryContext& context)
    : Config(getTestConfig(config), context) {}

TestConfig::~TestConfig() {
  hostmap.reset();
  npmap.reset();
}

bool TestConfig::getMetadata(Network::ConnectionSocket& socket) {
  // fake setting the local address. It remains the same as required by the test
  // infra, but it will be marked as restored as required by the original_dst
  // cluster.
  socket.connectionInfoProvider().restoreLocalAddress(original_dst_address);

  // TLS filter chain matches this, make namespace part of this (e.g.,
  // "default")?
  socket.setDetectedTransportProtocol("cilium:default");

  // This must be the full domain name
  socket.setRequestedServerName("localhost");

  std::string pod_ip;
  uint64_t source_identity;
  uint64_t destination_identity;
  if (is_ingress_) {
    source_identity = 1;
    destination_identity = 173;
    pod_ip = original_dst_address->ip()->addressAsString();
    ENVOY_LOG_MISC(debug, "INGRESS POD_IP: {}", pod_ip);
  } else {
    source_identity = 173;
    auto ip = socket.connectionInfoProvider().localAddress()->ip();
    destination_identity = hosts_->resolve(ip);
    pod_ip = ip->addressAsString();
    ENVOY_LOG_MISC(debug, "EGRESS POD_IP: {}", pod_ip);
  }
  auto policy = getPolicy(pod_ip);
  if (policy == nullptr) {
    ENVOY_LOG_MISC(warn, "tests.bpf_metadata ({}): No policy found for {}",
                   is_ingress_ ? "ingress" : "egress", pod_ip);
    return false;
  }

  auto port = original_dst_address->ip()->port();

  // Set metadata for policy based listener filter chain matching
  // Note: tls_inspector may overwrite this value, if it executes after us!
  std::string l7proto;
  if (policy &&
      policy->useProxylib(is_ingress_, port, is_ingress_ ? source_identity : destination_identity,
                          l7proto)) {
    std::vector<absl::string_view> protocols;
    protocols.emplace_back(l7proto);
    socket.setRequestedApplicationProtocols(protocols);
    ENVOY_LOG_MISC(info, "setRequestedApplicationProtocols({})", l7proto);
  }

  socket.addOption(std::make_shared<Cilium::SocketOption>(policy, 0, source_identity, is_ingress_,
                                                          false, port, std::move(pod_ip), nullptr,
                                                          nullptr, nullptr, shared_from_this()));

  return true;
}

} // namespace BpfMetadata
} // namespace Cilium

namespace Server {
namespace Configuration {

class TestBpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Network::ListenerFilterFactoryCb createListenerFilterFactoryFromProto(
      const Protobuf::Message& proto_config,
      const Network::ListenerFilterMatcherSharedPtr& listener_filter_matcher,
      ListenerFactoryContext& context) override {

    initTestMaps(context);

    auto config = std::make_shared<Cilium::BpfMetadata::TestConfig>(
        MessageUtil::downcastAndValidate<const ::cilium::TestBpfMetadata&>(
            proto_config, context.messageValidationVisitor()),
        context);

    return [listener_filter_matcher,
            config](Network::ListenerFilterManager& filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(listener_filter_matcher,
                                     std::make_unique<Cilium::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::TestBpfMetadata>();
  }

  std::string name() const override { return "test_bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
REGISTER_FACTORY(TestBpfMetadataConfigFactory, NamedListenerFilterConfigFactory);

} // namespace Configuration
} // namespace Server

} // namespace Envoy
