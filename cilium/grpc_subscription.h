#pragma once

#include <cstdint>
#include <functional>
#include <memory>

#include "envoy/common/callback.h"
#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher_thread_deletable.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Cilium {

class CiliumTestPeer;

inline constexpr absl::string_view NetworkPolicyTypeUrl =
    "type.googleapis.com/cilium.NetworkPolicy";
inline constexpr absl::string_view NetworkPolicyResourceTypeUrl =
    "type.googleapis.com/cilium.NetworkPolicyResource";

class ManagedGrpcSubscription : public Event::DispatcherThreadDeletable,
                                public Envoy::Config::SubscriptionCallbacks,
                                public Logger::Loggable<Logger::Id::config>,
                                public std::enable_shared_from_this<ManagedGrpcSubscription> {
public:
  using DecoderFactory =
      std::function<Envoy::Config::OpaqueResourceDecoderSharedPtr(absl::string_view type_url)>;
  using SubscriptionFactoryForTest =
      std::function<std::unique_ptr<Envoy::Config::Subscription>(bool use_delta_xds)>;

  ManagedGrpcSubscription(absl::string_view type_url,
                          const envoy::config::core::v3::ConfigSource& config_source,
                          DecoderFactory decoder_factory,
                          Server::Configuration::CommonFactoryContext& context,
                          Stats::ScopeSharedPtr scope, bool subscribe = true);
  ~ManagedGrpcSubscription() override = default;

  const envoy::config::core::v3::ConfigSource& getConfigSource() const {
    return current_config_.config_source_;
  }

  // A healthy Delta NPRDS stream remains active until it closes.
  void configure(const envoy::config::core::v3::ConfigSource& config_source);

  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason reason,
                            const EnvoyException* e) final;

protected:
  void subscribe(absl::string_view type_url = {});

  // A supported NPRDS server supplies a nonempty initial snapshot, even without local Endpoints.
  // Empty later deltas are ordinary updates, not negotiation responses.
  bool fallbackOnEmptyResponse(bool empty);

  void start() {
    if (subscription_ && !started_) {
      started_ = true;
      subscription_->start({});
    }
  };

  Stats::Scope& scope() { return *scope_; }

  absl::string_view getTypeUrl() const { return current_config_.type_url_; }
  bool usesDeltaXds() const {
    if (!current_config_.config_source_.has_api_config_source()) {
      return false;
    }
    const auto& api_type = current_config_.config_source_.api_config_source().api_type();
    return api_type == envoy::config::core::v3::ApiConfigSource::DELTA_GRPC ||
           api_type == envoy::config::core::v3::ApiConfigSource::AGGREGATED_DELTA_GRPC;
  }
  bool connected() const { return connected_; }
  bool started() const { return started_; }
  uint64_t streamGeneration() const { return stream_generation_; }

  void onStreamEvent(uint64_t subscription_id, Envoy::Config::GrpcMuxStreamEvent event);

private:
  friend class CiliumTestPeer;

  void create();
  void scheduleSubscribe(absl::string_view type_url);

  struct XdsConfig {
    absl::string_view type_url_; // Refers to a static protocol type URL.
    envoy::config::core::v3::ConfigSource config_source_;
  };

  // The desired type is fixed for the lifetime of the subscription. Policy streams prefer NPRDS
  // and may fall back to NPDS until the transport closes; listener updates only change the source.
  XdsConfig desired_config_;
  XdsConfig current_config_;

  DecoderFactory decoder_factory_;
  Server::Configuration::CommonFactoryContext& context_;
  Stats::ScopeSharedPtr scope_;

  Common::CallbackHandlePtr stream_event_handle_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  uint64_t subscription_id_{0};
  uint64_t stream_generation_{1};
  uint64_t response_generation_{0};
  bool connected_{false};
  bool started_{false};
  bool fallback_pending_{false};

  SubscriptionFactoryForTest factory_for_test_;
};
using ManagedGrpcSubscriptionSharedPtr = std::shared_ptr<ManagedGrpcSubscription>;

} // namespace Cilium
} // namespace Envoy
