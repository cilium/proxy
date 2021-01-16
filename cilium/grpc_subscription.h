#pragma once

#include "common/config/grpc_subscription_impl.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/grpc/async_client.h"
#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"

namespace Envoy {
namespace Cilium {

std::unique_ptr<Config::GrpcSubscriptionImpl> subscribe(
    const std::string& type_url, const LocalInfo::LocalInfo& local_info,
    Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
    Random::RandomGenerator& random, Stats::Scope& scope,
    Config::SubscriptionCallbacks& callbacks,
    Config::OpaqueResourceDecoder& resource_decoder);

}  // namespace Cilium
}  // namespace Envoy
