#pragma once

#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/common/config/opaque_resource_decoder_impl.h"
#include "source/common/http/header_utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/target_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/tls/context_config_impl.h"
#include "source/server/transport_socket_config_impl.h"

#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/npds.pb.validate.h"
#include "cilium/conntrack.h"

namespace Envoy {
namespace Cilium {

// PortRangeCompare is used for as std::less replacement for port range keys.
//
// All port ranges in the map have non-overlapping keys, which allows total ordering needed for
// ordered map containers. When inserting new ranges, any range overlap will be flagged as a
// "duplicate" entry, as overlapping keys are considered equal (as neither is strictly less than the
// other given this comparison predicate).
// On lookups we'll set both ends of the port range to the same port number, which will find the one
// range that it overlaps with, if one exists.
typedef std::pair<uint16_t, uint16_t> PortRange;
struct PortRangeCompare {
  bool operator()(const PortRange& a, const PortRange& b) const {
    // return true if range 'a.first - a.second' is below range 'b.first - b.second'.
    return a.second < b.first;
  }
};

class PortNetworkPolicyRules;
typedef std::list<PortNetworkPolicyRules> RulesList;

// PolicyMap is keyed by port ranges, and contains a list of PortNetworkPolicyRules's applicable
// to this range. A list is needed as rules may come from multiple sources (e.g., resulting from
// use of named ports and numbered ports in Cilium Network Policy at the same time).
typedef absl::btree_map<PortRange, RulesList, PortRangeCompare> PolicyMap;

// PortPolicy holds a reference to a set of rules in a policy map that apply to the given port.
// Methods then iterate through the set to determine if policy allows or denies. This is needed to
// support multiple rules on the same port, like when named ports are used, or when deny policies
// may be present.
class PortPolicy : public Logger::Loggable<Logger::Id::config> {
protected:
  friend class PortNetworkPolicy;
  friend class AllowAllEgressPolicyInstanceImpl;
  PortPolicy(const PolicyMap& map, const RulesList& wildcard_rules, uint16_t port);

public:
  // useProxylib returns true if a proxylib parser should be used.
  // 'l7_proto' is set to the parser name in that case.
  bool useProxylib(uint32_t remote_id, std::string& l7_proto) const;
  // HTTP-layer policy check. 'headers' and 'log_entry' may be manipulated by the policy.
  bool allowed(uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const;
  // Network-layer policy check
  bool allowed(uint32_t remote_id, absl::string_view sni) const;
  // Envoy filter metadata policy check
  bool allowed(uint32_t remote_id, const envoy::config::core::v3::Metadata& metadata) const;
  // getServerTlsContext returns the server TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  Ssl::ContextSharedPtr getServerTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const;
  // getClientTlsContext returns the client TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  Ssl::ContextSharedPtr getClientTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const;

private:
  bool for_range(std::function<bool(const PortNetworkPolicyRules&, bool& denied)> allowed) const;
  bool for_first_range(std::function<bool(const PortNetworkPolicyRules&)> f) const;

  const PolicyMap& map_;
  const RulesList& wildcard_rules_;
  const PolicyMap::const_iterator port_rules_; // iterator to 'map_'
};

class IPAddressPair {
public:
  IPAddressPair(){};
  IPAddressPair(Network::Address::InstanceConstSharedPtr& ipv4,
                Network::Address::InstanceConstSharedPtr& ipv6)
      : ipv4_(ipv4), ipv6_(ipv6){};
  IPAddressPair(const cilium::NetworkPolicy& proto);

  Network::Address::InstanceConstSharedPtr ipv4_{};
  Network::Address::InstanceConstSharedPtr ipv6_{};
};

class PolicyInstance {
public:
  virtual ~PolicyInstance() = default;

  virtual bool allowed(bool ingress, uint32_t remote_id, uint16_t port,
                       Envoy::Http::RequestHeaderMap& headers,
                       Cilium::AccessLog::Entry& log_entry) const PURE;

  virtual bool allowed(bool ingress, uint32_t remote_id, absl::string_view sni,
                       uint16_t port) const PURE;

  // Returned pointer must not be stored for later use!
  virtual const PortPolicy findPortPolicy(bool ingress, uint16_t port) const PURE;

  // Returns true if the policy specifies l7 protocol for the connection, and
  // returns the l7 protocol string in 'l7_proto'
  virtual bool useProxylib(bool ingress, uint32_t remote_id, uint16_t port,
                           std::string& l7_proto) const PURE;

  virtual const std::string& conntrackName() const PURE;

  virtual uint32_t getEndpointID() const PURE;

  virtual const IPAddressPair& getEndpointIPs() const PURE;

  virtual std::string String() const PURE;
};
using PolicyInstanceConstSharedPtr = std::shared_ptr<const PolicyInstance>;

class PolicyInstanceImpl;

class ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject,
                             public Logger::Loggable<Logger::Id::config> {
public:
  std::map<std::string, std::shared_ptr<const PolicyInstanceImpl>> policies_;

  void Update(std::vector<std::shared_ptr<PolicyInstanceImpl>>& added,
              std::vector<std::string>& deleted, const std::string& version_info);
};

class NetworkPolicyDecoder : public Envoy::Config::OpaqueResourceDecoder {
public:
  NetworkPolicyDecoder() : validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {}

  // Config::OpaqueResourceDecoder
  ProtobufTypes::MessagePtr decodeResource(const ProtobufWkt::Any& resource) override {
    auto typed_message = std::make_unique<cilium::NetworkPolicy>();
    // If the Any is a synthetic empty message (e.g. because the resource field
    // was not set in Resource, this might be empty, so we shouldn't decode.
    if (!resource.type_url().empty()) {
      MessageUtil::anyConvertAndValidate<cilium::NetworkPolicy>(resource, *typed_message,
                                                                validation_visitor_);
    }
    return typed_message;
  }

  std::string resourceName(const Protobuf::Message& resource) override {
    return fmt::format("{}", dynamic_cast<const cilium::NetworkPolicy&>(resource).endpoint_id());
  }

private:
  ProtobufMessage::ValidationVisitor& validation_visitor_;
};

class NetworkPolicyMap : public Singleton::Instance,
                         public Envoy::Config::SubscriptionCallbacks,
                         public std::enable_shared_from_this<NetworkPolicyMap>,
                         public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(Server::Configuration::FactoryContext& context);
  NetworkPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct);
  ~NetworkPolicyMap() {
    ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap({}): NetworkPolicyMap is deleted NOW!", name_);
  }

  // subscription_->start() calls onConfigUpdate(), which uses
  // shared_from_this(), which cannot be called before a shared
  // pointer is formed by the caller of the constructor, hence this
  // can't be called from the constructor!
  void startSubscription();

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
  }

  const PolicyInstanceConstSharedPtr
  GetPolicyInstance(const std::string& endpoint_policy_name) const;

  static PolicyInstanceConstSharedPtr AllowAllEgressPolicy;

  bool exists(const std::string& endpoint_policy_name) const {
    return GetPolicyInstanceImpl(endpoint_policy_name).get() != nullptr;
  }

  // run the given function after all the threads have scheduled
  void runAfterAllThreads(std::function<void()>) const;

  // Config::SubscriptionCallbacks
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) override {
    // NOT IMPLEMENTED YET.
    UNREFERENCED_PARAMETER(added_resources);
    UNREFERENCED_PARAMETER(removed_resources);
    UNREFERENCED_PARAMETER(system_version_info);
    return absl::OkStatus();
  }
  void onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                            const EnvoyException* e) override;

  Server::Configuration::TransportSocketFactoryContext& transportFactoryContext() const {
    return *transport_factory_context_;
  }

private:
  const std::shared_ptr<const PolicyInstanceImpl>&
  GetPolicyInstanceImpl(const std::string& endpoint_policy_name) const;

  void pause();
  void resume();

  bool isNewStream();

  static uint64_t instance_id_;

  Server::Configuration::ServerFactoryContext& context_;
  ThreadLocal::TypedSlot<ThreadLocalPolicyMap> tls_map_;
  const std::string local_ip_str_;
  std::string name_;
  Stats::ScopeSharedPtr scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Init::ManagerImpl> version_init_manager_;
  std::shared_ptr<Init::TargetImpl> version_init_target_;
  std::shared_ptr<Init::WatcherImpl> version_init_watcher_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;

  Cilium::CtMapSharedPtr ctmap_;

  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  Envoy::Config::ScopedResume resume_;

  ProtobufTypes::MessagePtr dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;
};

} // namespace Cilium
} // namespace Envoy
