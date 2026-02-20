#pragma once

#include <chrono>
#include <memory>
#include <string>

#include "envoy/common/random_generator.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/local_info/local_info.h"
#include "envoy/stats/scope.h"
#include "envoy/upstream/cluster_manager.h"

#include "source/extensions/config_subscription/grpc/grpc_mux_context.h"
#include "source/extensions/config_subscription/grpc/grpc_mux_impl.h"
#include "source/extensions/config_subscription/grpc/grpc_subscription_impl.h"

namespace Envoy {
namespace Cilium {

// Cilium XDS API config source. Used for all Cilium XDS.
extern envoy::config::core::v3::ConfigSource cilium_xds_api_config;

// GrpcMux wrapper to get access to control plane identifier
class GrpcMuxImpl : public Config::GrpcMuxImpl {
public:
  explicit GrpcMuxImpl(Config::GrpcMuxContext& grpc_mux_context)
      : Config::GrpcMuxImpl(grpc_mux_context) {}

  ~GrpcMuxImpl() override = default;

  void onStreamEstablished() override {
    new_stream_ = true;
    Config::GrpcMuxImpl::onStreamEstablished();
  }

  // isNewStream returns true for the first call after a new stream has been established
  bool isNewStream() {
    bool new_stream = new_stream_;
    new_stream_ = false;
    return new_stream;
  }

private:
  bool new_stream_ = true;
};

std::unique_ptr<Config::GrpcSubscriptionImpl>
subscribe(const std::string& type_url, const LocalInfo::LocalInfo& local_info,
          Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
          Random::RandomGenerator& random, Stats::Scope& scope,
          Config::SubscriptionCallbacks& callbacks,
          Config::OpaqueResourceDecoderSharedPtr resource_decoder,
          std::chrono::milliseconds init_fetch_timeout = std::chrono::milliseconds(0));

} // namespace Cilium
} // namespace Envoy
