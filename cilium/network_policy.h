#pragma once

#include <fmt/format.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/common/pure.h"
#include "envoy/common/regex.h"
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
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/common/thread.h"
#include "source/common/init/target_impl.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/npds.pb.validate.h" // IWYU pragma: keep
#include "cilium/conntrack.h"
#include "re2/re2.h"

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
using PortRange = std::pair<uint16_t, uint16_t>;
struct PortRangeCompare {
  bool operator()(const PortRange& a, const PortRange& b) const {
    // return true if range 'a.first - a.second' is below range 'b.first - b.second'.
    return a.second < b.first;
  }
};

class PortNetworkPolicyRules;

// PolicyMap is keyed by port ranges, and contains a list of PortNetworkPolicyRules's applicable
// to this range. A list is needed as rules may come from multiple sources (e.g., resulting from
// use of named ports and numbered ports in Cilium Network Policy at the same time).
using PolicyMap = absl::btree_map<PortRange, PortNetworkPolicyRules, PortRangeCompare>;

struct RuleVerdict {
  bool have_verdict;
  bool allowed;
  uint32_t precedence;
};

// PortPolicy holds a reference to a set of rules in a policy map that apply to the given port.
// Methods then iterate through the set to determine if policy allows or denies. This is needed to
// support multiple rules on the same port, like when named ports are used, or when deny policies
// may be present.
class PortPolicy : public Logger::Loggable<Logger::Id::config> {
protected:
  friend class PortNetworkPolicy;
  friend class DenyAllPolicyInstanceImpl;
  friend class AllowAllEgressPolicyInstanceImpl;
  PortPolicy(const PolicyMap& map, uint16_t port);

public:
  // If hasHttpRules() returns false, then HTTP policy enforcement can be skipped,
  // given that Network layer policy has already been enforced.
  bool hasHttpRules() const { return has_http_rules_; }

  // useProxylib returns true if a proxylib parser should be used.
  // 'l7_proto' is set to the parser name in that case.
  bool useProxylib(uint16_t proxy_id, uint32_t remote_id, std::string& l7_proto) const;
  // HTTP-layer policy check. 'headers' and 'log_entry' may be manipulated by the policy.
  bool allowed(uint16_t proxy_id, uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const;
  // Network-layer policy check
  bool allowed(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni) const;
  // Envoy filter metadata policy check
  bool allowed(uint16_t proxy_id, uint32_t remote_id,
               const envoy::config::core::v3::Metadata& metadata) const;
  // getServerTlsContext returns the server TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  // If '*config' is nullptr and 'raw_socket_allowed' is 'true' on return then the policy
  // allows the connection without TLS and a raw socket should be used.
  Ssl::ContextSharedPtr getServerTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const;
  // getClientTlsContext returns the client TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  // If '*config' is nullptr and 'raw_socket_allowed' is 'true' on return then the policy
  // allows the connection without TLS and a raw socket should be used.
  Ssl::ContextSharedPtr getClientTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const;

private:
  bool
  forRange(std::function<RuleVerdict(const PortNetworkPolicyRules&, uint32_t)> get_verdict) const;
  bool forFirstRange(std::function<RuleVerdict(const PortNetworkPolicyRules&, uint32_t)> f) const;

  const PolicyMap& map_;
  // using raw pointers by design:
  // - pointer to distinguish between no rules and empty rules
  // - not using shared pointer to not allow a worker thread to hold the last reference to policy
  //   rule(s), as they must be destructed from the main thread only.
  // - lifetime on policy updates is managed explicitly by posting a lambda to all worker threads
  //   before the old rules are deleted; worker thread drop references to policy rules before
  //   returning to the event loop, so after the posted lambda executes it is safe to delete the old
  //   rules.
  const PortNetworkPolicyRules* wildcard_rules_;
  const PortNetworkPolicyRules* port_rules_;
  const bool has_http_rules_;
};

class IpAddressPair {
public:
  IpAddressPair() = default;
  IpAddressPair(Network::Address::InstanceConstSharedPtr& ipv4,
                Network::Address::InstanceConstSharedPtr& ipv6)
      : ipv4_(ipv4), ipv6_(ipv6) {};
  IpAddressPair(const cilium::NetworkPolicy& proto);

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

  virtual bool allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
                       Envoy::Http::RequestHeaderMap& headers,
                       Cilium::AccessLog::Entry& log_entry) const PURE;

  virtual bool allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                       uint16_t port) const PURE;

  virtual const PortPolicy findPortPolicy(bool ingress, uint16_t port) const PURE;

  // Returns true if the policy specifies l7 protocol for the connection, and
  // returns the l7 protocol string in 'l7_proto'
  virtual bool useProxylib(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
                           std::string& l7_proto) const PURE;

  virtual const std::string& conntrackName() const PURE;

  virtual uint32_t getEndpointID() const PURE;

  virtual const IpAddressPair& getEndpointIPs() const PURE;

  virtual std::string string() const PURE;

  virtual void tlsWrapperMissingPolicyInc() const PURE;
};
using PolicyInstanceConstSharedPtr = std::shared_ptr<const PolicyInstance>;

class PolicyInstanceImpl;

class NetworkPolicyDecoder : public Envoy::Config::OpaqueResourceDecoder {
public:
  NetworkPolicyDecoder() : validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {}

  // Config::OpaqueResourceDecoder
  ProtobufTypes::MessagePtr decodeResource(const Protobuf::Any& resource) override {
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

class NetworkPolicyMapImpl : public Envoy::Config::SubscriptionCallbacks,
                             public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMapImpl(Server::Configuration::FactoryContext& context);
  ~NetworkPolicyMapImpl() override;

  void startSubscription();

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
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

  Regex::Engine& regexEngine() const { return context_.regexEngine(); }

  void tlsWrapperMissingPolicyInc() const;

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

  const PolicyInstance* getPolicyInstanceImpl(const std::string& endpoint_policy_name) const;

  void removeInitManager();

  bool isNewStream();

  static uint64_t instance_id_;

  Server::Configuration::ServerFactoryContext& context_;
  std::atomic<const RawPolicyMap*> map_ptr_;
  Stats::ScopeSharedPtr npds_stats_scope_;
  Stats::ScopeSharedPtr policy_stats_scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;

  std::unique_ptr<Envoy::Config::Subscription> subscription_;

protected:
  friend class NetworkPolicyMap;
  friend class CiliumNetworkPolicyTest;

  void setConntrackMap(Cilium::CtMapSharedPtr& ct) { ctmap_ = ct; }

  Cilium::CtMapSharedPtr ctmap_;
  PolicyStats stats_;
};

class DenyAllPolicyInstanceImpl;
class AllowAllEgressPolicyInstanceImpl;

class NetworkPolicyMap : public Singleton::Instance, public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(Server::Configuration::FactoryContext& context);
  NetworkPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct);
  ~NetworkPolicyMap() override;

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    getImpl().startSubscription(std::move(subscription));
  }

  const PolicyInstance& getPolicyInstance(const std::string& endpoint_policy_name,
                                          bool allow_egress) const;

  static DenyAllPolicyInstanceImpl DenyAllPolicy;
  static PolicyInstance& getDenyAllPolicy();
  static AllowAllEgressPolicyInstanceImpl AllowAllEgressPolicy;
  static PolicyInstance& getAllowAllEgressPolicy();

  bool exists(const std::string& endpoint_policy_name) const {
    return getImpl().getPolicyInstanceImpl(endpoint_policy_name) != nullptr;
  }

  NetworkPolicyMapImpl& getImpl() const { return *impl_; }

private:
  Server::Configuration::ServerFactoryContext& context_;
  std::unique_ptr<NetworkPolicyMapImpl> impl_;

  ProtobufTypes::MessagePtr dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;
};
using NetworkPolicyMapSharedPtr = std::shared_ptr<const NetworkPolicyMap>;

// SniPattern implements a matcher for allowed SNI patterns.
// See comment for `getValidPatternRE()` method to understand structure of a valid pattern.
//
// SniPattern supports two types of wildcards in match pattern:
// - '*' matches any number of valid DNS characters within a subdomain boundary.
// - '**' matches any non empty DNS pattern (across subdomain boundary).
//
// Additionaly "*" is a special pattern that matches any valid DNS.
//
// Examples:
//
// - `*.cilium.io` matches all first-level subdomains of `cilium.io`:
//   - Matches: `www.cilium.io`, `blog.cilium.io`
//   - Does NOT match: `cilium.io`, `foo.bar.cilium.io`, `kubernetes.io`
//
// - `*cilium.io` matches `cilium.io` and any domain ending with the `cilium.io` suffix:
//   - Matches: `cilium.io`, `sub-cilium.io`, `subcilium.io`
//   - Does NOT match: `www.cilium.io`, `blog.cilium.io`
//
// - `sub*.cilium.io` matches subdomains of `cilium.io` that start with the "sub" prefix:
//   - Matches: `sub.cilium.io`, `subdomain.cilium.io`
//   - Does NOT match: `www.cilium.io`, `blog-sub.cilium.io`, `blog.sub.cilium.io`, `cilium.io`
//
// - `**.cilium.io` matches all subdomains of `cilium.io` at any depth:
//   - Matches: `www.cilium.io`, `test.app.cilium.io`
//   - Does NOT match: `cilium.io`
class SniPattern : public Logger::Loggable<Logger::Id::config> {
public:
  explicit SniPattern(const Regex::Engine& engine, absl::string_view sni);

  // Helper method to check that the provided match pattern is valid and can be used
  // to construct an instance of SniPattern. A valid match pattern should:
  //
  // - Contain only valid DNS characters('-a-zA-Z0-9_') and the wildcard specifier ('*')
  // - No consecutive wildcard specifiers, except two for multiple whole subdomain matches.
  // - Not have a trailing '.'
  // - Not have an empty subdomain (multiple consecutive '.' are not allowed)
  // - Empty pattern is only allowed due to testing, it does not match anything
  static bool isValid(absl::string_view pattern) {
    return pattern.length() == 0 || re2::RE2::FullMatch(pattern, getValidPatternRE());
  }

  bool matches(const absl::string_view sni) const {
    // The constructed match pattern or match name will be case sensitive.
    // Convert to lower case before checking.
    auto const lower_sni = absl::AsciiStrToLower(sni);
    if (isExplicitFullMatch()) {
      return match_name_ == lower_sni;
    }

    if (matcher_) {
      return matcher_->match(lower_sni); // Anchored match
    }
    return false;
  }

  void toString(std::string& res) const {
    if (isExplicitFullMatch()) {
      res.append(fmt::format("\"{}\"", match_name_));
    } else if (matcher_) {
      res.append(fmt::format("\"{}\"", matcher_->pattern()));
    } else {
      res.append("\"\"");
    }
  }

private:
  // Returns regular expression to check for a valid DNS pattern with optional additional
  // wildcard specifier ('*') characters.
  static const re2::RE2& getValidPatternRE() {
    CONSTRUCT_ON_FIRST_USE(re2::RE2, "(([*]{1,2}|[*]?[-a-zA-Z0-9_]+([*][-a-zA-Z0-9_]+)*[*]?)[.])*"
                                     "([*]{1,2}|[*]?[-a-zA-Z0-9_]+([*][-a-zA-Z0-9_]+)*[*]?)");
  }

  bool isExplicitFullMatch() const { return !match_name_.empty(); }

  std::string match_name_;
  std::shared_ptr<const Envoy::Regex::CompiledMatcher> matcher_;
};

} // namespace Cilium
} // namespace Envoy
