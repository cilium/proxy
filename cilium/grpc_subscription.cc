#include "cilium/grpc_subscription.h"

#include <fmt/format.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/annotations/resource.pb.h"
#include "envoy/common/callback.h"
#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/custom_config_validators.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/config/subscription_factory.h"
#include "envoy/grpc/async_client.h"
#include "envoy/server/factory_context.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/common/common/assert.h"
#include "source/common/common/backoff_strategy.h"
#include "source/common/common/logger.h"
#include "source/common/config/utility.h"
#include "source/common/grpc/common.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/extensions/config_subscription/grpc/grpc_mux_context.h"
#include "source/extensions/config_subscription/grpc/grpc_mux_impl.h"
#include "source/extensions/config_subscription/grpc/grpc_subscription_impl.h"
#include "source/extensions/config_subscription/grpc/new_grpc_mux_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

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
  NopConfigValidatorsImpl() = default;

  void executeValidators(absl::string_view,
                         const std::vector<Envoy::Config::DecodedResourcePtr>&) override {}
  void executeValidators(absl::string_view, const std::vector<Envoy::Config::DecodedResourcePtr>&,
                         const Protobuf::RepeatedPtrField<std::string>&) override {}
};

bool configSourceUsesDeltaXds(const envoy::config::core::v3::ConfigSource& config_source) {
  if (!config_source.has_api_config_source()) {
    return false;
  }
  const auto& api_type = config_source.api_config_source().api_type();
  return api_type == envoy::config::core::v3::ApiConfigSource::DELTA_GRPC ||
         api_type == envoy::config::core::v3::ApiConfigSource::AGGREGATED_DELTA_GRPC;
}

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

} // namespace

void ManagedGrpcSubscription::create() {
  auto initial_fetch_timeout = Config::Utility::configSourceInitialFetchTimeout(config_source_);
  Config::SubscriptionStats stats = Config::Utility::generateStats(*scope_);
  Envoy::Config::SubscriptionOptions options;

  std::shared_ptr<Config::GrpcMux> grpc_mux;
  bool is_aggregated =
      config_source_.config_source_specifier_case() == envoy::config::core::v3::ConfigSource::kAds;
  if (is_aggregated) {
    grpc_mux = std::static_pointer_cast<Config::GrpcMux>(context_.xdsManager().adsMux());
  } else {
    auto& api_config_source = config_source_.api_config_source();
    THROW_IF_NOT_OK(Config::Utility::checkApiConfigSourceSubscriptionBackingCluster(
        context_.clusterManager().primaryClusters(), api_config_source));

    // No-op custom validators
    Envoy::Config::CustomConfigValidatorsPtr nop_config_validators =
        std::make_unique<NopConfigValidatorsImpl>();
    auto factory_or_error = Config::Utility::factoryForGrpcApiConfigSource(
        context_.clusterManager().grpcAsyncClientManager(), api_config_source, *scope_, true, 0,
        false);
    THROW_IF_NOT_OK_REF(factory_or_error.status());

    absl::StatusOr<Config::RateLimitSettings> rate_limit_settings_or_error =
        Config::Utility::parseRateLimitSettings(api_config_source);
    THROW_IF_NOT_OK_REF(rate_limit_settings_or_error.status());

    const auto& api_type = api_config_source.api_type();
    bool use_delta = api_type == envoy::config::core::v3::ApiConfigSource::DELTA_GRPC ||
                     api_type == envoy::config::core::v3::ApiConfigSource::AGGREGATED_DELTA_GRPC;
    const auto& service_method = use_delta ? deltaGrpcMethod(type_url_) : sotwGrpcMethod(type_url_);

    Config::GrpcMuxContext grpc_mux_context{
        THROW_OR_RETURN_VALUE(factory_or_error.value()->createUncachedRawAsyncClient(),
                              Grpc::RawAsyncClientPtr),
        /*failover_async_client_=*/nullptr,
        context_.mainThreadDispatcher(),
        service_method,
        context_.localInfo(),
        rate_limit_settings_or_error.value(),
        *scope_,
        std::move(nop_config_validators),
        /*xds_resources_delegate_=*/absl::nullopt,
        /*xds_config_tracker_=*/absl::nullopt,
        std::make_unique<JitteredExponentialBackOffStrategy>(
            Config::SubscriptionFactory::RetryInitialDelayMs,
            Config::SubscriptionFactory::RetryMaxDelayMs, context_.api().randomGenerator()),
        /*target_xds_authority_=*/"",
        /*eds_resources_cache_=*/nullptr, // EDS cache is only used for ADS.
        /*skip_subsequent_node_=*/api_config_source.set_node_on_first_message_only(),
        /*load_stats_reporter_factory_=*/nullptr,
    };

    grpc_mux = use_delta ? std::static_pointer_cast<Config::GrpcMux>(
                               std::make_shared<Config::NewGrpcMuxImpl>(grpc_mux_context))
                         : std::static_pointer_cast<Config::GrpcMux>(
                               std::make_shared<Config::GrpcMuxImpl>(grpc_mux_context));
  }

  // The subscription owns the callback handle, so stream callbacks cannot outlive this object.
  auto stream_event_callback = [this, id = subscription_id_](Config::GrpcMuxStreamEvent event) {
    onStreamEvent(id, event);
  };
  stream_event_handle_ = grpc_mux->addStreamEventCallback(stream_event_callback);
  if (grpc_mux->grpcStreamConnected()) {
    stream_event_callback(Config::GrpcMuxStreamEvent::Established);
  }

  subscription_ = std::make_unique<Config::GrpcSubscriptionImpl>(
      grpc_mux, *this, decoder_factory_(), stats, type_url_, context_.mainThreadDispatcher(),
      initial_fetch_timeout, is_aggregated, options);
}

ManagedGrpcSubscription::ManagedGrpcSubscription(
    absl::string_view type_url, DecoderFactory decoder_factory,
    const envoy::config::core::v3::ConfigSource& config_source,
    Server::Configuration::CommonFactoryContext& context, Stats::ScopeSharedPtr scope,
    bool do_subscribe)
    : type_url_(type_url), desired_config_source_(config_source), config_source_(config_source),
      decoder_factory_(std::move(decoder_factory)), context_(context), scope_(scope) {
  RELEASE_ASSERT(decoder_factory_ != nullptr, "ManagedGrpcSubscription needs a decoder factory");
  if (do_subscribe) {
    subscribe();
  }
}

void ManagedGrpcSubscription::subscribe() {
  connected_ = false;
  config_source_ = desired_config_source_;
  ++subscription_id_;

  if (factory_for_test_) {
    subscription_ = factory_for_test_(configSourceUsesDeltaXds(config_source_));
  } else {
    create();
  }
}

void ManagedGrpcSubscription::configure(
    const envoy::config::core::v3::ConfigSource& config_source) {
  desired_config_source_ = config_source;
  if (subscription_ == nullptr) {
    config_source_ = desired_config_source_;
    return;
  }
  maybeRecreateInDesiredMode(/*transport_closed=*/false);
}

void ManagedGrpcSubscription::onStreamEvent(uint64_t subscription_id,
                                            Config::GrpcMuxStreamEvent event) {
  if (subscription_id != subscription_id_) {
    return;
  }

  switch (event) {
  case Config::GrpcMuxStreamEvent::Established:
    ++stream_generation_;
    connected_ = true;
    break;
  case Config::GrpcMuxStreamEvent::Closed:
    if (!connected_) {
      return;
    }
    connected_ = false;

    if (factory_for_test_) {
      maybeRecreateInDesiredMode(/*transport_closed=*/true);
      return;
    }

    context_.mainThreadDispatcher().post(
        [weak_this = weak_from_this(), subscription_id = subscription_id_]() {
          if (auto shared_this = weak_this.lock()) {
            if (subscription_id != shared_this->subscription_id_) {
              return;
            }
            shared_this->maybeRecreateInDesiredMode(/*transport_closed=*/true);
          }
        });
    break;
  }
}

void ManagedGrpcSubscription::maybeRecreateInDesiredMode(bool transport_closed) {
  if (subscription_ && (connected_ || !transport_closed)) {
    if (connected_ && configSourceUsesDeltaXds(config_source_)) {
      // Keep delta on a connected subscription until transport closes.
      return;
    }
    if (Protobuf::util::MessageDifferencer::Equals(config_source_, desired_config_source_)) {
      // Let the current subscription keep going when it is already in the desired mode.
      return;
    }
  }
  subscribe();
  start();
}

void ManagedGrpcSubscription::onConfigUpdateFailed(Config::ConfigUpdateFailureReason reason,
                                                   const EnvoyException* e) {
  if (e != nullptr) {
    ENVOY_LOG(warn,
              "Cilium xDS update for {} on stream {} failed with reason {}, keeping existing "
              "config: {}",
              type_url_, streamGeneration(), static_cast<int>(reason), e->what());
    return;
  }
  ENVOY_LOG(debug,
            "Cilium xDS update for {} on stream {} failed with reason {}, keeping existing config.",
            type_url_, streamGeneration(), static_cast<int>(reason));
}

} // namespace Cilium
} // namespace Envoy
