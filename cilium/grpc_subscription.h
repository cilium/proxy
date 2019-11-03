#pragma once

#include "envoy/api/v2/core/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/grpc/async_client.h"

#include "common/config/grpc_mux_impl.h"
#include "common/config/grpc_mux_subscription_impl.h"
#include "common/config/utility.h"

namespace Envoy {
namespace Cilium {

class GrpcSubscriptionImpl : public Config::Subscription {
public:
  GrpcSubscriptionImpl(const LocalInfo::LocalInfo& local_info, Grpc::RawAsyncClientPtr async_client,
                       Event::Dispatcher& dispatcher, Runtime::RandomGenerator& random,
                       const Protobuf::MethodDescriptor& service_method, absl::string_view type_url,
                       Config::SubscriptionCallbacks& callbacks, Config::SubscriptionStats stats,
                       Stats::Scope& scope, const Config::RateLimitSettings& rate_limit_settings,
                       std::chrono::milliseconds init_fetch_timeout, bool skip_subsequent_node)
    : callbacks_(callbacks), type_url_(type_url),
        grpc_mux_(std::make_shared<Config::GrpcMuxImpl>(local_info, std::move(async_client),
							dispatcher, service_method, random, scope,
							rate_limit_settings, skip_subsequent_node)),
        grpc_mux_subscription_(grpc_mux_, callbacks_, stats, type_url, dispatcher,
                               init_fetch_timeout) {}

  void pause() { grpc_mux_->pause(type_url_); }
  void resume() { grpc_mux_->resume(type_url_); }

  // Config::Subscription
  void start(const std::set<std::string>& resource_names) override {
    // Subscribe first, so we get failure callbacks if grpc_mux_->start() fails.
    grpc_mux_subscription_.start(resource_names);
    grpc_mux_->start();
  }

  void updateResourceInterest(const std::set<std::string>& update_to_these_names) override {
    grpc_mux_subscription_.updateResourceInterest(update_to_these_names);
  }

  std::shared_ptr<Config::GrpcMuxImpl> grpcMux() { return grpc_mux_; }

private:
  Config::SubscriptionCallbacks& callbacks_;
  std::string type_url_;
  std::shared_ptr<Config::GrpcMuxImpl> grpc_mux_;
  Config::GrpcMuxSubscriptionImpl grpc_mux_subscription_;
};

std::unique_ptr<GrpcSubscriptionImpl>
subscribe(const std::string& type_url, const std::string& grpc_method,
	  const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope, Envoy::Config::SubscriptionCallbacks& callbacks);

} // namespace Cilium
} // namespace Envoy
