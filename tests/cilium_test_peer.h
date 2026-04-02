#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "cilium/grpc_subscription.h"
#include "cilium/host_map.h"
#include "cilium/network_policy.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"

namespace Envoy {
namespace Cilium {

class CiliumTestPeer {
public:
  using SubscriptionFactory = ManagedGrpcSubscription::SubscriptionFactoryForTest;

  static void setSubscription(ManagedGrpcSubscription& target,
                              std::unique_ptr<Config::Subscription>&& subscription) {
    target.subscription_ = std::move(subscription);
    target.config_source_ = target.desired_config_source_;
    target.connected_ = false;
  }

  static void setSubscription(PolicyHostMap& target,
                              std::unique_ptr<Config::Subscription>&& subscription) {
    setSubscription(static_cast<ManagedGrpcSubscription&>(target), std::move(subscription));
  }

  static void setSubscription(NetworkPolicyMap& target,
                              std::unique_ptr<Config::Subscription>&& subscription) {
    setSubscription(target.managedSubscription(), std::move(subscription));
  }

  static void setSubscriptionFactory(ManagedGrpcSubscription& target, SubscriptionFactory factory) {
    target.factory_for_test_ = std::move(factory);
  }

  static void setSubscriptionFactory(NetworkPolicyMap& target, SubscriptionFactory factory) {
    setSubscriptionFactory(target.managedSubscription(), std::move(factory));
  }

  static void start(ManagedGrpcSubscription& target) { target.start(); }

  static void start(PolicyHostMap& target) { start(static_cast<ManagedGrpcSubscription&>(target)); }

  static void resetStream(ManagedGrpcSubscription& target) { ++target.stream_generation_; }

  static void resetStream(NetworkPolicyMap& target) { resetStream(target.managedSubscription()); }

  static uint64_t subscriptionId(ManagedGrpcSubscription& target) {
    return target.subscription_id_;
  }

  static void onStreamEvent(ManagedGrpcSubscription& target, Config::GrpcMuxStreamEvent event) {
    target.onStreamEvent(subscriptionId(target), event);
  }

  static void onStreamEvent(NetworkPolicyMap& target, Config::GrpcMuxStreamEvent event) {
    onStreamEvent(target.managedSubscription(), event);
  }

  static bool connected(const ManagedGrpcSubscription& target) { return target.connected_; }

  static bool connected(const NetworkPolicyMap& target) {
    return connected(target.managedSubscription());
  }

  static Config::SubscriptionCallbacks& subscriptionCallbacks(ManagedGrpcSubscription& target) {
    return target;
  }

  static Config::SubscriptionCallbacks& subscriptionCallbacks(NetworkPolicyMap& target) {
    return subscriptionCallbacks(target.managedSubscription());
  }

  static PolicyStats& policyStats(const NetworkPolicyMap& target) { return target.stats(); }

  static PolicyInstanceConstSharedPtr
  policyInstanceShared(const NetworkPolicyMap& target, const std::string& endpoint_policy_name) {
    return target.getPolicyInstanceShared(endpoint_policy_name);
  }
};

} // namespace Cilium
} // namespace Envoy
