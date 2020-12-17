#pragma once

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/grpc/async_client.h"
#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/config/grpc_subscription_impl.h"

namespace Envoy {
namespace Cilium {

/**
  * Wrapper to expose gRPC mux pause/resume.
  */
class GrpcSubscriptionImpl : public Config::GrpcSubscriptionImpl {
public:
  GrpcSubscriptionImpl(Config::GrpcMuxSharedPtr grpc_mux, Config::SubscriptionCallbacks& callbacks,
                       Config::OpaqueResourceDecoder& resource_decoder,
                       Config::SubscriptionStats stats, absl::string_view type_url,
                       Event::Dispatcher& dispatcher, std::chrono::milliseconds init_fetch_timeout,
                       bool is_aggregated)
    : Config::GrpcSubscriptionImpl(grpc_mux, callbacks, resource_decoder, stats, type_url, dispatcher,
				   init_fetch_timeout, is_aggregated),
    type_url_(type_url), grpc_mux_(grpc_mux) {}

  void pause() { grpc_mux_->pause(type_url_); }
  void resume() { grpc_mux_->resume(type_url_); }

private:
  std::string type_url_;
  Config::GrpcMuxSharedPtr grpc_mux_;
};


std::unique_ptr<GrpcSubscriptionImpl>
subscribe(const std::string& type_url, const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope, Config::SubscriptionCallbacks& callbacks,
	  Config::OpaqueResourceDecoder& resource_decoder);

} // namespace Cilium
} // namespace Envoy
