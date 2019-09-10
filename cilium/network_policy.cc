#include "cilium/network_policy.h"
#include "cilium/api/npds.pb.validate.h"
#include "cilium/grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t NetworkPolicyMap::instance_id_ = 0;

// This is used directly for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(ThreadLocal::SlotAllocator& tls)
    : tls_(tls.allocateSlot()), validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {
  instance_id_++;
  name_ = "cilium.policymap." + fmt::format("{}", instance_id_) + ".";
  ENVOY_LOG(debug, "NetworkPolicyMap({}) created.", name_);  

  tls_->set([&](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<ThreadLocalPolicyMap>();
  });
}

// This is used in production
NetworkPolicyMap::NetworkPolicyMap(const LocalInfo::LocalInfo& local_info,
				   Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
				   Runtime::RandomGenerator& random, Stats::Scope &scope,
				   ThreadLocal::SlotAllocator& tls)
  : NetworkPolicyMap(tls) {
  scope_ = scope.createScope(name_);
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicy", "cilium.NetworkPolicyDiscoveryService.StreamNetworkPolicies", local_info, cm, dispatcher, random, *scope_, *this);
}

void NetworkPolicyMap::onConfigUpdate(const Protobuf::RepeatedPtrField<ProtobufWkt::Any>& resources, const std::string& version_info) {
  ENVOY_LOG(debug, "NetworkPolicyMap::onConfigUpdate({}), {} resources, version: {}", name_, resources.size(), version_info);

  std::unordered_set<std::string> keeps;
  std::unordered_set<std::string> ct_maps_to_keep;

  // Collect a shared vector of policies to be added
  auto to_be_added = std::make_shared<std::vector<std::shared_ptr<PolicyInstance>>>();
  for (const auto& resource: resources) {
    auto config = MessageUtil::anyConvert<cilium::NetworkPolicy>(resource);
    ENVOY_LOG(debug, "Received Network Policy for endpoint {} in onConfigUpdate() version {}: {}", config.name(), version_info, config.DebugString());
    keeps.insert(config.name());
    ct_maps_to_keep.insert(config.conntrack_map_name());

    MessageUtil::validate(config, validation_visitor_);

    // First find the old config to figure out if an update is needed.
    const uint64_t new_hash = MessageUtil::hash(config);
    const auto& old_policy = GetPolicyInstance(config.name());
    if (old_policy && old_policy->hash_ == new_hash &&
	Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
      ENVOY_LOG(debug, "New policy is equal to old one, not updating.");
      continue;
    }

    // May throw
    to_be_added->emplace_back(std::make_shared<PolicyInstance>(new_hash, config));
  }

  // Collect a shared vector of policy names to be removed
  auto to_be_deleted = std::make_shared<std::vector<std::string>>();
  // Collect a shared vector of conntrack maps to close
  auto cts_to_be_closed = std::make_shared<std::unordered_set<std::string>>();
  for (auto& pair: tls_->getTyped<ThreadLocalPolicyMap>().policies_) {
    if (keeps.find(pair.first) == keeps.end()) {
      to_be_deleted->emplace_back(pair.first);
    }
    // insert conntrack map names we don't want to keep and that have not been already inserted.
    auto& ct_map_name = pair.second->conntrack_map_name_;
    if (ct_maps_to_keep.find(ct_map_name) == ct_maps_to_keep.end() &&
	cts_to_be_closed->find(ct_map_name) == cts_to_be_closed->end()) {
      ENVOY_LOG(debug, "Closing conntrack map {}", ct_map_name);
      cts_to_be_closed->insert(ct_map_name);
    }
  }

  // 'this' may be already deleted when the worker threads get to execute the updates.
  // Manage this by taking a weak_ptr on 'this' and then, when the worker thread gets
  // to execute the posted lambda, try to convert the weak_ptr to a temporary shared_ptr.
  // If that succeeds then this NetworkPolicyMap is still alive and the policy
  // should be updated.
  std::weak_ptr<NetworkPolicyMap> weak_this = shared_from_this();

  // Execute changes on all threads.
  tls_->runOnAllThreads([weak_this, to_be_added, to_be_deleted]() -> void {
      std::shared_ptr<NetworkPolicyMap> shared_this = weak_this.lock();
      if (shared_this && shared_this->tls_->get().get() != nullptr) {
	ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap::onConfigUpdate(): Starting updates on the next thread");
	auto& npmap = shared_this->tls_->getTyped<ThreadLocalPolicyMap>().policies_;
	for (const auto& policy_name: *to_be_deleted) {
	  ENVOY_LOG(debug, "Cilium deleting removed network policy for endpoint {}", policy_name);
	  npmap.erase(policy_name);
	}
	for (const auto& new_policy: *to_be_added) {
	  ENVOY_LOG(debug, "Cilium updating network policy for endpoint {}", new_policy->policy_proto_.name());
	  npmap[new_policy->policy_proto_.name()] = new_policy;
	}
      } else {
	// Keep this at info level for now to see if this happens in the wild
	ENVOY_LOG(warn, "Skipping stale network policy update");
      }
    },
    // delete old cts when all threads have updated their policies
    [weak_this, cts_to_be_closed]() -> void {
      if (cts_to_be_closed->size() > 0) {
	std::shared_ptr<NetworkPolicyMap> shared_this = weak_this.lock();
	if (shared_this && shared_this->ctmap_ && shared_this->tls_->get().get() != nullptr) {
	  shared_this->ctmap_->closeMaps(cts_to_be_closed);
	}
      }
    });
}

void NetworkPolicyMap::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason, const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
}

} // namespace Cilium
} // namespace Envoy
