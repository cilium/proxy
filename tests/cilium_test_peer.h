#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "cilium/grpc_subscription.h"
#include "cilium/policy_host_map.h"
#include "cilium/network_policy.h"
#include "envoy/config/grpc_mux.h"
#include "envoy/config/subscription.h"

namespace Envoy {
namespace Cilium {

class CiliumTestPeer {
public:
  using SubscriptionFactory = ManagedGrpcSubscription::SubscriptionFactoryForTest;

  static void setSubscription(ManagedGrpcSubscription& target,
                              std::unique_ptr<Config::Subscription>&& subscription,
                              absl::string_view type_url = {}) {
    target.subscription_ = std::move(subscription);
    target.current_config_ = target.desired_config_;
    if (!type_url.empty()) {
      target.current_config_.type_url_ = type_url;
    }
    target.fallback_pending_ = false;
    target.response_generation_ = 0;
    target.connected_ = false;
    target.started_ = false;
  }

  static void setSubscription(PolicyHostMap& target,
                              std::unique_ptr<Config::Subscription>&& subscription) {
    setSubscription(static_cast<ManagedGrpcSubscription&>(target), std::move(subscription));
  }

  static void setSubscription(NetworkPolicyMap& target,
                              std::unique_ptr<Config::Subscription>&& subscription,
                              absl::string_view type_url = NetworkPolicyTypeUrl) {
    setSubscription(target.managedSubscription(), std::move(subscription), type_url);
  }

  static absl::string_view subscriptionTypeUrl(NetworkPolicyMap& target) {
    return target.managedSubscription().getTypeUrl();
  }

  static void setSubscriptionFactory(ManagedGrpcSubscription& target, SubscriptionFactory factory) {
    target.factory_for_test_ = std::move(factory);
  }

  static void setSubscriptionFactory(NetworkPolicyMap& target, SubscriptionFactory factory) {
    setSubscriptionFactory(target.managedSubscription(), std::move(factory));
  }

  static void subscribe(ManagedGrpcSubscription& target) { target.subscribe(); }
  static void subscribe(PolicyHostMap& target) {
    subscribe(static_cast<ManagedGrpcSubscription&>(target));
  }
  static void subscribe(NetworkPolicyMap& target) { subscribe(target.managedSubscription()); }

  static void start(ManagedGrpcSubscription& target) { target.start(); }
  static void start(PolicyHostMap& target) { start(static_cast<ManagedGrpcSubscription&>(target)); }
  static void start(NetworkPolicyMap& target) { start(target.managedSubscription()); }

  static void resetStream(ManagedGrpcSubscription& target) {
    ++target.stream_generation_;
    target.fallback_pending_ = false;
  }
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

  static auto policyShared(const NetworkPolicyMap& target,
                           const std::string& endpoint_policy_name) {
    return target.getPolicyShared(endpoint_policy_name);
  }
};

} // namespace Cilium
} // namespace Envoy
