#pragma once

#include <fmt/format.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/common/pure.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/server/config_tracker.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/singleton/instance.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/common/thread.h"
#include "source/common/init/target_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h" // IWYU pragma: keep
#include "source/common/protobuf/utility.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/npds.pb.validate.h" // IWYU pragma: keep
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
  friend class DenyAllPolicyInstanceImpl;
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
  // If '*config' is nullptr and 'raw_socket_allowed' is 'true' on return then the policy
  // allows the connection without TLS and a raw socket should be used.
  Ssl::ContextSharedPtr getServerTlsContext(uint32_t remote_id, absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const;
  // getClientTlsContext returns the client TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  // If '*config' is nullptr and 'raw_socket_allowed' is 'true' on return then the policy
  // allows the connection without TLS and a raw socket should be used.
  Ssl::ContextSharedPtr getClientTlsContext(uint32_t remote_id, absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const;

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
  virtual ~PolicyInstance() {
    if (!Thread::MainThread::isMainOrTestThread()) {
      IS_ENVOY_BUG("PolicyInstance: Destructor executing in a worker thread, while "
                   "only main thread should destruct xDS resources");
    }
  };

  virtual bool allowed(bool ingress, uint32_t remote_id, uint16_t port,
                       Envoy::Http::RequestHeaderMap& headers,
                       Cilium::AccessLog::Entry& log_entry) const PURE;

  virtual bool allowed(bool ingress, uint32_t remote_id, absl::string_view sni,
                       uint16_t port) const PURE;

  virtual const PortPolicy findPortPolicy(bool ingress, uint16_t port) const PURE;

  // Returns true if the policy specifies l7 protocol for the connection, and
  // returns the l7 protocol string in 'l7_proto'
  virtual bool useProxylib(bool ingress, uint32_t remote_id, uint16_t port,
                           std::string& l7_proto) const PURE;

  virtual const std::string& conntrackName() const PURE;

  virtual uint32_t getEndpointID() const PURE;

  virtual const IPAddressPair& getEndpointIPs() const PURE;

  virtual std::string String() const PURE;

  virtual void tlsWrapperMissingPolicyInc() const PURE;
};
using PolicyInstanceConstSharedPtr = std::shared_ptr<const PolicyInstance>;

class PolicyInstanceImpl;

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

/**
 * All Cilium L7 filter stats. @see stats_macros.h
 */
// clang-format off
#define ALL_CILIUM_POLICY_STATS(COUNTER, HISTOGRAM)	\
  COUNTER(updates_total)				\
  COUNTER(updates_rejected)				\
  COUNTER(tls_wrapper_missing_policy)
// clang-format on

/**
 * Struct definition for all policy stats. @see stats_macros.h
 */
struct PolicyStats {
  ALL_CILIUM_POLICY_STATS(GENERATE_COUNTER_STRUCT, GENERATE_HISTOGRAM_STRUCT)
};

using RawPolicyMap = absl::flat_hash_map<std::string, std::shared_ptr<const PolicyInstanceImpl>>;

class DenyAllPolicyInstanceImpl;
class AllowAllEgressPolicyInstanceImpl;

class NetworkPolicyMap : public Singleton::Instance,
                         public Envoy::Config::SubscriptionCallbacks,
                         public std::enable_shared_from_this<NetworkPolicyMap>,
                         public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(Server::Configuration::FactoryContext& context);
  NetworkPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct);
  ~NetworkPolicyMap();

  // subscription_->start() calls onConfigUpdate(), which uses
  // shared_from_this(), which cannot be called before a shared
  // pointer is formed by the caller of the constructor, hence this
  // can't be called from the constructor!
  void startSubscription();

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
  }

  const PolicyInstance& GetPolicyInstance(const std::string& endpoint_policy_name,
                                          bool allow_egress) const;

  static DenyAllPolicyInstanceImpl DenyAllPolicy;
  static PolicyInstance& GetDenyAllPolicy();
  static AllowAllEgressPolicyInstanceImpl AllowAllEgressPolicy;
  static PolicyInstance& GetAllowAllEgressPolicy();

  bool exists(const std::string& endpoint_policy_name) const {
    return GetPolicyInstanceImpl(endpoint_policy_name) != nullptr;
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

  void tlsWrapperMissingPolicyInc() const { stats_.tls_wrapper_missing_policy_.inc(); }

private:
  // Helpers for atomic swap of the policy map pointer.
  //
  // store() is only used for the initialization of the map during construction.
  // exchange() is used to atomically swap in a new map, the old map pointer is returned.
  // Once a map is stored or swapped in to the atomic pointer by the main thread, it may be "loaded"
  // from the atomic pointer by any thread. This is why the load returns a const pointer.
  //
  // For the loaded pointer to be safe to use, we must use acquire/release memory ordering:
  // - when a pointer stored or swapped in, 'std::memory_order_release' informs the compiler to make
  //   sure it is not reordering any write operations into the map to happen after the pointer is
  //   written, and emits CPU instructions to also make the CPU out-of-order-execution logic to not
  //   reorder any write operations to happen after the pointer itself is written. This guarantees
  //   that the map is not modified after the point when the worker threads can observe the new
  //   pointer value, i.e., the map is actaully immutable (const) from that point forward.
  // - when the pointer is read (by a worker thread) 'std::memory_order_acquire' in the load
  //   operation informs the compiler to emit CPU instructions to make the CPU
  //   out-of-order-execution logic to not reorder any reads from the new map to happen before the
  //   pointer itself is read, so that no values from the map are read before the map was "released"
  //   by the store or exchange operation.
  //
  // Typically it is easier to think about the release part of the acquire/release semantics, as at
  // the point of the store or exchange operation the compiler and the CPU know the location of the
  // map in memory before and after the pointer is stored, so that without
  // 'std::memory_order_release' there is an understandable risk of such write after release
  // happening. On the acquire side it seems less likely that the compiler or the CPU could know the
  // new map pointer value in advance and even try to reorder any read operations to happen before
  // the pointer is actually read. But consider the typical case where the pointer value is actually
  // not changing between consecutice load operations. The compiler or the CPU could speculate that
  // to be the case and read some values from the old memory location. 'std::memory_order_acquire'
  // tells the compiler (which then "tells" the CPU) that this can not be done, and all reads must
  // actually happen after the pointer value is loaded, be it a new one or the same as before.
  //
  const RawPolicyMap* load() const { return map_ptr_.load(std::memory_order_acquire); }
  void store(const RawPolicyMap* map) { map_ptr_.store(map, std::memory_order_release); }
  const RawPolicyMap* exchange(const RawPolicyMap* map) {
    return map_ptr_.exchange(map, std::memory_order_release);
  }

  const PolicyInstance* GetPolicyInstanceImpl(const std::string& endpoint_policy_name) const;

  void removeInitManager();

  bool isNewStream();

  friend class CiliumNetworkPolicyTest;

  static uint64_t instance_id_;

  Server::Configuration::ServerFactoryContext& context_;
  std::atomic<const RawPolicyMap*> map_ptr_;
  Stats::ScopeSharedPtr npds_stats_scope_;
  Stats::ScopeSharedPtr policy_stats_scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;

  Cilium::CtMapSharedPtr ctmap_;
  absl::flat_hash_set<std::string> ctmaps_to_be_closed_;

  std::unique_ptr<Envoy::Config::Subscription> subscription_;

  ProtobufTypes::MessagePtr dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;

protected:
  PolicyStats stats_;
};
using NetworkPolicyMapSharedPtr = std::shared_ptr<const NetworkPolicyMap>;

struct SNIPattern {
  std::string pattern;

  explicit SNIPattern(const std::string& p) : pattern(absl::AsciiStrToLower(p)) {}

  bool matches(const absl::string_view sni) const {
    if (pattern.empty() || sni.empty()) {
      return false;
    }
    auto const lower_sni = absl::AsciiStrToLower(sni);
    // Perform lower case exact match if there is no wildcard prefix
    if (!pattern.starts_with("*")) {
      return pattern == lower_sni;
    }

    // Pattern is "**.<domain>"
    if (pattern.starts_with("**.")) {
      return lower_sni.ends_with(pattern.substr(2));
    }

    // Pattern is "*.<domain>"
    if (pattern.starts_with("*.")) {
      auto const sub_pattern = pattern.substr(1);
      if (!lower_sni.ends_with(sub_pattern)) {
        return false;
      }
      auto const prefix = lower_sni.substr(0, sni.size() - sub_pattern.size());
      // Make sure that only and exactly one label is before the wildcard
      return !prefix.empty() && prefix.find_first_of(".") == std::string::npos;
    }

    return false;
  }

  void toString(std::string& res) const { res.append(fmt::format("\"{}\"", pattern)); }
};

} // namespace Cilium
} // namespace Envoy
