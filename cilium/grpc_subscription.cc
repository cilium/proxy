#include "cilium/grpc_subscription.h"

#include "envoy/api/v2/core/base.pb.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

std::unique_ptr<Envoy::Config::Subscription>
subscribe(const std::string& type_url, const std::string& grpc_method,
	  const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope) {
  // Hard-coded Cilium gRPC cluster
  // Note: No rate-limit settings are used, consider if needed.
  envoy::api::v2::core::ApiConfigSource api_config_source{};
  api_config_source.set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
  api_config_source.add_grpc_services()->mutable_envoy_grpc()->set_cluster_name("xds-grpc-cilium"); 

  Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(cm.clusters(), api_config_source);
  const auto* method = Protobuf::DescriptorPool::generated_pool()->FindMethodByName(grpc_method);

  if (method == nullptr) {
    throw EnvoyException(fmt::format("gRPC method {} not found.", grpc_method));
  }

  return std::make_unique<Config::GrpcSubscriptionImpl>(
                local_info,
		Config::Utility::factoryForGrpcApiConfigSource(cm.grpcAsyncClientManager(),
							       api_config_source,
							       scope)->create(),
		dispatcher, random, *method, type_url, Config::Utility::generateStats(scope), scope,
		Config::Utility::parseRateLimitSettings(api_config_source),
		std::chrono::milliseconds(0) /* no initial fetch timeout */);
}

} // namespace Cilium
} // namespace Envoy
