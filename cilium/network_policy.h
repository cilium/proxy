#pragma once

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "common/http/header_utility.h"
#include "common/protobuf/message_validator_impl.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/http/header_map.h"

#include "cilium/api/npds.pb.h"
#include "cilium/conntrack.h"

namespace Envoy {
namespace Cilium {

class PolicyInstance;

class NetworkPolicyMap : public Singleton::Instance,
                         public Envoy::Config::SubscriptionCallbacks,
                         public std::enable_shared_from_this<NetworkPolicyMap>,
                         public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(ThreadLocal::SlotAllocator& tls);
  NetworkPolicyMap(const LocalInfo::LocalInfo& local_info, Upstream::ClusterManager& cm,
		   Event::Dispatcher& dispatcher, Runtime::RandomGenerator& random,
		   Stats::Scope &scope, ThreadLocal::SlotAllocator& tls);
  ~NetworkPolicyMap() {
    ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap({}): NetworkPolicyMap is deleted NOW!", name_);
  }

  // subscription_->start() calls onConfigUpdate(), which uses
  // shared_from_this(), which cannot be called before a shared
  // pointer is formed by the caller of the constructor, hence this
  // can't be called from the constructor!
  void startSubscription() { subscription_->start({}); }

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
    startSubscription();
  }

  void setPolicyNotifier(Cilium::CtMapSharedPtr& ct) { ctmap_ = ct; }

  struct ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject {
    std::map<std::string, std::shared_ptr<const PolicyInstance>> policies_;
  };

  const std::shared_ptr<const PolicyInstance>& GetPolicyInstance(const std::string& endpoint_policy_name) const {
    if (tls_->get().get() == nullptr) {
      ENVOY_LOG(warn, "Cilium L7 NetworkPolicyMap::GetPolicyInstance(): NULL TLS object!");
      return null_instance_;
    }
    const ThreadLocalPolicyMap& map = tls_->getTyped<ThreadLocalPolicyMap>();
    auto it = map.policies_.find(endpoint_policy_name);
    if (it == map.policies_.end()) {
      return null_instance_;
    }
    return it->second;
  }

  bool exists(const std::string& endpoint_policy_name) const {
    return GetPolicyInstance(endpoint_policy_name).get() != nullptr;
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const Protobuf::RepeatedPtrField<ProtobufWkt::Any>& resources,
		      const std::string& version_info) override;
  void onConfigUpdate(const Protobuf::RepeatedPtrField<envoy::api::v2::Resource>& added_resources,
		      const Protobuf::RepeatedPtrField<std::string>& removed_resources,
		      const std::string& system_version_info) override {
    // NOT IMPLEMENTED YET.
    UNREFERENCED_PARAMETER(added_resources);
    UNREFERENCED_PARAMETER(removed_resources);
    UNREFERENCED_PARAMETER(system_version_info);
  }
  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason, const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return MessageUtil::anyConvert<cilium::NetworkPolicy>(resource).name();
  }

private:
  ThreadLocal::SlotPtr tls_;
  ProtobufMessage::ValidationVisitor& validation_visitor_;
  Stats::ScopePtr scope_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  const std::shared_ptr<const PolicyInstance> null_instance_{nullptr};
  static uint64_t instance_id_;
  std::string name_;
  Cilium::CtMapSharedPtr ctmap_;
};

class PolicyInstance {
public:
  PolicyInstance(uint64_t hash, const cilium::NetworkPolicy& proto)
    : conntrack_map_name_(proto.conntrack_map_name()), hash_(hash), policy_proto_(proto),
      ingress_(policy_proto_.ingress_per_port_policies()),
      egress_(policy_proto_.egress_per_port_policies()) {}

  std::string conntrack_map_name_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;

protected:
  class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
    HttpNetworkPolicyRule(const cilium::HttpNetworkPolicyRule& rule) {
      ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
      for (const auto& header: rule.headers()) {
	headers_.emplace_back(std::make_unique<Envoy::Http::HeaderUtility::HeaderData>(header));
	const auto& header_data = *headers_.back();
	ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={}",
		  header_data.name_.get(),
		  header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Range
		  ? fmt::format("[{}-{})", header_data.range_.start(), header_data.range_.end())
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Value
		  ? header_data.value_
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Regex
		  ? "<REGEX>" : "<UNKNOWN>");
      }
    }

    bool Matches(const Envoy::Http::HeaderMap& headers) const {
      // Empty set matches any headers.
      return Envoy::Http::HeaderUtility::matchHeaders(headers, headers_);
    }

    std::vector<Envoy::Http::HeaderUtility::HeaderDataPtr> headers_; // Allowed if empty.
  };
    
  class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRule(const cilium::PortNetworkPolicyRule& rule)
      : l7_proto_(rule.l7_proto()) {
      for (const auto& remote: rule.remote_policies()) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {}", remote);
	allowed_remotes_.emplace(remote);
      }
      if (rule.has_http_rules()) {
	for (const auto& http_rule: rule.http_rules().http_rules()) {
	  http_rules_.emplace_back(http_rule);
	}
      }
    }

    bool Matches(uint64_t remote_id) const {
      // Remote ID must match if we have any.
      if (allowed_remotes_.size() > 0) {
	auto search = allowed_remotes_.find(remote_id);
	if (search == allowed_remotes_.end()) {
	  return false;
	}
      }
      return true;
    }

    bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
      if (!Matches(remote_id)) {
	return false;
      }
      if (http_rules_.size() > 0) {
	for (const auto& rule: http_rules_) {
	  if (rule.Matches(headers)) {
	    return true;
	  }
	}
	return false;
      }
      // Empty set matches any payload
      return true;
    }

    bool useProxylib(std::string& l7_proto) const {
      if (l7_proto_.length() > 0) {
	ENVOY_LOG(debug, "Cilium L7 PortNetworkPolicyRules::useProxylib(): returning {}", l7_proto_);
	l7_proto = l7_proto_;
	return true;
      }
      return false;
    }

    std::unordered_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
    std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
    std::string l7_proto_{};
  };

  class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRules(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
      if (rules.size() == 0) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow everything.");
      }
      for (const auto& it: rules) {
	if (it.has_http_rules()) {
	  have_http_rules_ = true;
	}
	rules_.emplace_back(PortNetworkPolicyRule(it));
      }
    }

    bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
      if (!have_http_rules_) {
	// If there are no L7 rules, host proxy will not create a proxy redirect at all,
	// whereby the decicion made by the bpf datapath is final. Emulate the same behavior
	// in the sidecar by allowing such traffic.
	// TODO: This will need to be revised when non-bpf datapaths are to be supported.
	return true;
      }
      // Empty set matches any payload from anyone
      if (rules_.size() == 0) {
	return true;
      }
      for (const auto& rule: rules_) {
	if (rule.Matches(remote_id, headers)) {
	  return true;
	}
      }
      return false;
    }

    const PortNetworkPolicyRule* findPortPolicy(uint64_t remote_id) const {
      for (const auto& rule: rules_) {
	if (rule.Matches(remote_id)) {
	  return &rule;
	}
      }
      return nullptr;
    }

    std::vector<PortNetworkPolicyRule> rules_; // Allowed if empty.
    bool have_http_rules_{};
  };
    
  class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicy(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
      for (const auto& it: rules) {
	// Only TCP supported for HTTP
	if (it.protocol() == envoy::api::v2::core::SocketAddress::TCP) {
	  // Port may be zero, which matches any port.
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP policy for port {}", it.port());
	  if (!rules_.emplace(it.port(), PortNetworkPolicyRules(it.rules())).second) {
	    throw EnvoyException("PortNetworkPolicy: Duplicate port number");
	  }
	} else {
	  ENVOY_LOG(debug, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
	}
      }
    }

    bool Matches(uint32_t port, uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
      bool found_port_rule = false;
      auto it = rules_.find(port);
      if (it != rules_.end()) {
	if (it->second.Matches(remote_id, headers)) {
	  return true;
	}
	found_port_rule = true;
      }
      // Check for any rules that wildcard the port
      // Note: Wildcard port makes no sense for an L7 policy, but the policy could be a L3/L4 policy as well.
      it = rules_.find(0);
      if (it != rules_.end()) {
	if (it->second.Matches(remote_id, headers)) {
	  return true;
	}
	found_port_rule = true;
      }

      // No policy for the port was found. Cilium always creates a policy for redirects it
      // creates, so the host proxy never gets here. Sidecar gets all the traffic, which we need
      // to pass through since the bpf datapath already allowed it.
      return found_port_rule ? false : true;
    }

    const PortNetworkPolicyRule* findPortPolicy(uint32_t port, uint64_t remote_id) const {
      auto it = rules_.find(port);
      if (it != rules_.end()) {
	return it->second.findPortPolicy(remote_id);
      }
      return nullptr;
    }

    std::unordered_map<uint32_t, PortNetworkPolicyRules> rules_;
  };

public:
  bool Allowed(bool ingress, uint32_t port, uint64_t remote_id,
	       const Envoy::Http::HeaderMap& headers) const {
    return ingress
      ? ingress_.Matches(port, remote_id, headers)
      : egress_.Matches(port, remote_id, headers);
  }

  const PortNetworkPolicyRule* findPortPolicy(bool ingress, uint32_t port, uint64_t remote_id) const {
    return ingress
      ? ingress_.findPortPolicy(port, remote_id)
      : egress_.findPortPolicy(port, remote_id);
  }

  bool useProxylib(bool ingress, uint32_t port, uint64_t remote_id, std::string& l7_proto) const {
    const auto* port_policy = findPortPolicy(ingress, port, remote_id);
    if (port_policy != nullptr) {
      return port_policy->useProxylib(l7_proto);
    }
    return false;
  }

  std::string conntrackName() const {
    return conntrack_map_name_;
  }

private:
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

} // namespace Cilium
} // namespace Envoy
