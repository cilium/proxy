#pragma once

#include <string>

#include "common/config/grpc_subscription_impl.h"

namespace Envoy {
namespace Cilium {

std::unique_ptr<Envoy::Config::Subscription>
subscribe(const std::string& type_url, const std::string& grpc_method,
	  const LocalInfo::LocalInfo& local_info,
	  Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
	  Runtime::RandomGenerator& random, Stats::Scope &scope);

} // namespace Cilium
} // namespace Envoy
