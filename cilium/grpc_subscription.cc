#include "cilium/grpc_subscription.h"

#include "envoy/annotations/resource.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "common/config/grpc_mux_impl.h"
#include "common/config/grpc_subscription_impl.h"
#include "common/config/type_to_endpoint.h"
#include "common/config/utility.h"
#include "common/grpc/common.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

namespace {

// service RPC method fully qualified names.
struct Service {
  std::string sotw_grpc_method_;
  std::string delta_grpc_method_;
  std::string rest_method_;
};

// Map from resource type URL to service RPC methods.
using TypeUrlToServiceMap = std::unordered_map<std::string, Service>;

TypeUrlToServiceMap* buildTypeUrlToServiceMap() {
  auto* type_url_to_service_map = new TypeUrlToServiceMap();
  // This happens once in the lifetime of Envoy. We build a reverse map from resource type URL to
  // service methods. We explicitly enumerate all services, since DescriptorPool doesn't support
  // iterating over all descriptors, due its lazy load design, see
  // https://www.mail-archive.com/protobuf@googlegroups.com/msg04540.html.
  for (const std::string& service_name : {
           "cilium.NetworkPolicyDiscoveryService",
           "cilium.NetworkPolicyHostsDiscoveryService",
       }) {
    const auto* service_desc =
        Protobuf::DescriptorPool::generated_pool()->FindServiceByName(service_name);
    // TODO(htuch): this should become an ASSERT once all v3 descriptors are linked in.
    ASSERT(service_desc != nullptr, fmt::format("{} missing", service_name));
    ASSERT(service_desc->options().HasExtension(envoy::annotations::resource));
    const std::string resource_type_url = Grpc::Common::typeUrl(
        service_desc->options().GetExtension(envoy::annotations::resource).type());
    Service& service = (*type_url_to_service_map)[resource_type_url];
    // We populate the service methods that are known below, but it's possible that some services
    // don't implement all, e.g. VHDS doesn't support SotW or REST.
    for (int method_index = 0; method_index < service_desc->method_count(); ++method_index) {
      const auto& method_desc = *service_desc->method(method_index);
      if (absl::StartsWith(method_desc.name(), "Stream")) {
        service.sotw_grpc_method_ = method_desc.full_name();
      } else if (absl::StartsWith(method_desc.name(), "Delta")) {
        service.delta_grpc_method_ = method_desc.full_name();
      } else if (absl::StartsWith(method_desc.name(), "Fetch")) {
        service.rest_method_ = method_desc.full_name();
      } else {
        ASSERT(false, "Unknown xDS service method");
      }
    }
  }
  return type_url_to_service_map;
}

TypeUrlToServiceMap& typeUrlToServiceMap() {
  static TypeUrlToServiceMap* type_url_to_service_map = buildTypeUrlToServiceMap();
  return *type_url_to_service_map;
}

} // namespace

const Protobuf::MethodDescriptor& deltaGrpcMethod(absl::string_view type_url) {
  const auto it = typeUrlToServiceMap().find(static_cast<std::string>(type_url));
  ASSERT(it != typeUrlToServiceMap().cend());
  return *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
      it->second.delta_grpc_method_);
}

const Protobuf::MethodDescriptor& sotwGrpcMethod(absl::string_view type_url) {
  const auto it = typeUrlToServiceMap().find(static_cast<std::string>(type_url));
  ASSERT(it != typeUrlToServiceMap().cend());
  return *Protobuf::DescriptorPool::generated_pool()->FindMethodByName(
      it->second.sotw_grpc_method_);
}

std::unique_ptr<GrpcSubscriptionImpl>
subscribe(const std::string& type_url, const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope, Config::SubscriptionCallbacks& callbacks,
	  Config::OpaqueResourceDecoder& resource_decoder) {
  // Hard-coded Cilium gRPC cluster
  // Note: No rate-limit settings are used, consider if needed.
  envoy::config::core::v3::ApiConfigSource api_config_source{};
  api_config_source.set_set_node_on_first_message_only(true);
  api_config_source.set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
  api_config_source.add_grpc_services()->mutable_envoy_grpc()->set_cluster_name("xds-grpc-cilium"); 

  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.primaryClusters(), api_config_source);

  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);

  return std::make_unique<GrpcSubscriptionImpl>(
      std::make_shared<Config::GrpcMuxImpl>(
          local_info,
	  Config::Utility::factoryForGrpcApiConfigSource(cm.grpcAsyncClientManager(),
							 api_config_source, scope, true)
	      ->create(),
	  dispatcher, sotwGrpcMethod(type_url), api_config_source.transport_api_version(),
          random, scope, Config::Utility::parseRateLimitSettings(api_config_source),
          api_config_source.set_node_on_first_message_only()),
      callbacks, resource_decoder, stats, type_url, dispatcher,
      std::chrono::milliseconds(0) /* no initial fetch timeout */, /*is_aggregated*/ false);
}

} // namespace Cilium
} // namespace Envoy
