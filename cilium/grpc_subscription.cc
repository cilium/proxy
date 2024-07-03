#include "cilium/grpc_subscription.h"

#include "envoy/annotations/resource.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"

#include "source/common/config/type_to_endpoint.h"
#include "source/common/config/utility.h"
#include "source/common/grpc/common.h"
#include "source/common/protobuf/protobuf.h"
#include "source/extensions/config_subscription/grpc/grpc_mux_context.h"
#include "source/extensions/config_subscription/grpc/grpc_mux_impl.h"

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
using TypeUrlToServiceMap = absl::flat_hash_map<std::string, Service>;

TypeUrlToServiceMap* buildTypeUrlToServiceMap() {
  auto* type_url_to_service_map = new TypeUrlToServiceMap();
  // This happens once in the lifetime of Envoy. We build a reverse map from
  // resource type URL to service methods. We explicitly enumerate all services,
  // since DescriptorPool doesn't support iterating over all descriptors, due
  // its lazy load design, see
  // https://www.mail-archive.com/protobuf@googlegroups.com/msg04540.html.
  for (absl::string_view name : {
           "cilium.NetworkPolicyDiscoveryService",
           "cilium.NetworkPolicyHostsDiscoveryService",
       }) {
    const auto* service_desc =
        Protobuf::DescriptorPool::generated_pool()->FindServiceByName(std::string(name));
    // TODO(htuch): this should become an ASSERT once all v3 descriptors are
    // linked in.
    ASSERT(service_desc != nullptr, fmt::format("{} missing", name));
    ASSERT(service_desc->options().HasExtension(envoy::annotations::resource));
    const std::string resource_type_url = Grpc::Common::typeUrl(
        service_desc->options().GetExtension(envoy::annotations::resource).type());
    Service& service = (*type_url_to_service_map)[resource_type_url];
    // We populate the service methods that are known below, but it's possible
    // that some services don't implement all, e.g. VHDS doesn't support SotW or
    // REST.
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

class NopConfigValidatorsImpl : public Envoy::Config::CustomConfigValidators {
public:
  NopConfigValidatorsImpl() {}

  void executeValidators(absl::string_view,
                         const std::vector<Envoy::Config::DecodedResourcePtr>&) override {}
  void executeValidators(absl::string_view, const std::vector<Envoy::Config::DecodedResourcePtr>&,
                         const Protobuf::RepeatedPtrField<std::string>&) override {}
};

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

// Hard-coded Cilium gRPC cluster
// Note: No rate-limit settings are used, consider if needed.
envoy::config::core::v3::ConfigSource getCiliumXDSAPIConfig() {
  auto config_source = envoy::config::core::v3::ConfigSource();
  /* config_source.initial_fetch_timeout is set to 5 seconds.
   * This applies only to SDS Secrets for now, as for NPDS and NPHDS we explicitly set the timeout
   * as 0 (no timeout).
   */
  config_source.mutable_initial_fetch_timeout()->set_seconds(5);
  config_source.set_resource_api_version(envoy::config::core::v3::ApiVersion::V3);
  auto api_config_source = config_source.mutable_api_config_source();
  api_config_source->set_set_node_on_first_message_only(true);
  api_config_source->set_api_type(envoy::config::core::v3::ApiConfigSource::GRPC);
  api_config_source->set_transport_api_version(envoy::config::core::v3::ApiVersion::V3);
  api_config_source->add_grpc_services()->mutable_envoy_grpc()->set_cluster_name("xds-grpc-cilium");
  return config_source;
}

envoy::config::core::v3::ConfigSource cilium_xds_api_config = getCiliumXDSAPIConfig();

std::unique_ptr<Config::GrpcSubscriptionImpl>
subscribe(const std::string& type_url, const LocalInfo::LocalInfo& local_info,
          Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
          Random::RandomGenerator& random, Stats::Scope& scope,
          Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder,
          std::chrono::milliseconds init_fetch_timeout) {
  const envoy::config::core::v3::ApiConfigSource& api_config_source =
      cilium_xds_api_config.api_config_source();
  THROW_IF_NOT_OK(Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(
      cm.primaryClusters(), api_config_source));

  Config::SubscriptionStats stats = Config::Utility::generateStats(scope);
  Envoy::Config::SubscriptionOptions options;

  // No-op custom validators
  Envoy::Config::CustomConfigValidatorsPtr nop_config_validators =
      std::make_unique<NopConfigValidatorsImpl>();
  auto factory_or_error = Config::Utility::factoryForGrpcApiConfigSource(
      cm.grpcAsyncClientManager(), api_config_source, scope, true);
  THROW_IF_STATUS_NOT_OK(factory_or_error, throw);

  absl::StatusOr<Config::RateLimitSettings> rate_limit_settings_or_error =
      Config::Utility::parseRateLimitSettings(api_config_source);
  THROW_IF_STATUS_NOT_OK(rate_limit_settings_or_error, throw);

  Config::GrpcMuxContext grpc_mux_context{
      factory_or_error.value()->createUncachedRawAsyncClient(),
      /*dispatcher_=*/dispatcher,
      /*service_method_=*/sotwGrpcMethod(type_url),
      /*local_info_=*/local_info,
      /*rate_limit_settings_=*/rate_limit_settings_or_error.value(),
      /*scope_=*/scope,
      /*config_validators_=*/std::move(nop_config_validators),
      /*xds_resources_delegate_=*/absl::nullopt,
      /*xds_config_tracker_=*/absl::nullopt,
      /*backoff_strategy_=*/
      std::make_unique<JitteredExponentialBackOffStrategy>(
          Config::SubscriptionFactory::RetryInitialDelayMs,
          Config::SubscriptionFactory::RetryMaxDelayMs, random),
      /*target_xds_authority_=*/"",
      /*eds_resources_cache_=*/nullptr // EDS cache is only used for ADS.
  };

  return std::make_unique<Config::GrpcSubscriptionImpl>(
      std::make_shared<GrpcMuxImpl>(grpc_mux_context,
                                    api_config_source.set_node_on_first_message_only()),
      callbacks, resource_decoder, stats, type_url, dispatcher, init_fetch_timeout,
      /*is_aggregated*/ false, options);
}

} // namespace Cilium
} // namespace Envoy
