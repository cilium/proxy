#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

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

class ManagedGrpcSubscription : public Event::DispatcherThreadDeletable,
                                public Config::SubscriptionCallbacks,
                                public Logger::Loggable<Logger::Id::config>,
                                public std::enable_shared_from_this<ManagedGrpcSubscription> {
public:
  using DecoderFactory = std::function<Config::OpaqueResourceDecoderSharedPtr()>;
  using SubscriptionFactoryForTest =
      std::function<std::unique_ptr<Config::Subscription>(bool use_delta_xds)>;

  ManagedGrpcSubscription(absl::string_view type_url, DecoderFactory decoder_factory,
                          const envoy::config::core::v3::ConfigSource& config_source,
                          Server::Configuration::CommonFactoryContext& context,
                          Stats::ScopeSharedPtr scope, bool subscribe = true);
  ~ManagedGrpcSubscription() override = default;

  const envoy::config::core::v3::ConfigSource& getConfigSource() const { return config_source_; }

  // must be configured before subscribe()
  void configure(const envoy::config::core::v3::ConfigSource& config_source);

  void onConfigUpdateFailed(Config::ConfigUpdateFailureReason reason,
                            const EnvoyException* e) final;

protected:
  void subscribe();

  void start() {
    if (subscription_) {
      subscription_->start({});
    }
  };

  Stats::Scope& scope() { return *scope_; }

  bool connected() const { return connected_; }
  uint64_t streamGeneration() const { return stream_generation_; }

  void onStreamEvent(uint64_t subscription_id, Config::GrpcMuxStreamEvent event);

private:
  friend class CiliumTestPeer;

  void create();
  void maybeRecreateInDesiredMode(bool transport_closed);

  const std::string type_url_;
  // desired_config_source_ is used to store config updates from BpfMetadata filter.
  // Listeners can ask for different configs, so we may keep the existing config_source_
  // if it remains functional even if some BpfMetadata filters ask for something different.
  envoy::config::core::v3::ConfigSource desired_config_source_;
  envoy::config::core::v3::ConfigSource config_source_;
  DecoderFactory decoder_factory_;
  Server::Configuration::CommonFactoryContext& context_;
  Stats::ScopeSharedPtr scope_;

  Common::CallbackHandlePtr stream_event_handle_;
  std::unique_ptr<Config::Subscription> subscription_;
  uint64_t subscription_id_{0};
  uint64_t stream_generation_{1};
  bool connected_{false};

  SubscriptionFactoryForTest factory_for_test_;
};
using ManagedGrpcSubscriptionSharedPtr = std::shared_ptr<ManagedGrpcSubscription>;

} // namespace Cilium
} // namespace Envoy
