#include "cilium/network_policy.h"

#include <fmt/base.h>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <openssl/mem.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <ranges>
#include <string>
#include <typeinfo>
#include <utility>
#include <vector>

#include "absl/types/variant.h"
#include "envoy/admin/v3/init_dump.pb.h"
#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/common/optref.h"
#include "envoy/common/pure.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/init/manager.h"
#include "envoy/network/address.h"
#include "envoy/server/config_tracker.h"
#include "envoy/server/factory_context.h"
#include "envoy/server/transport_socket_config.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/http/header_utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/target_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_map.h"
#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/grpc_subscription.h"
#include "cilium/ipcache.h"
#include "cilium/secret_watcher.h"
#include "cilium/versioned.h"

namespace Envoy {
namespace Cilium {

// Supported verdict kinds
using RuleVerdict = enum {
  None = 0,
  Pass = 1,
  Allow = 2,
  Deny = 3,
};

} // namespace Cilium
} // namespace Envoy

// Envoy routes ENVOY_LOG() through spdlog, which formats its arguments with fmtlib.
namespace fmt {

template <> struct formatter<Envoy::Cilium::RuleVerdict> {
  constexpr auto parse(fmt::format_parse_context& ctx) { return ctx.begin(); }

  template <typename FormatContext>
  auto format(Envoy::Cilium::RuleVerdict verdict, FormatContext& ctx) const {
    absl::string_view name;
    switch (verdict) {
    case Envoy::Cilium::RuleVerdict::None:
      name = "NONE";
      break;
    case Envoy::Cilium::RuleVerdict::Allow:
      name = "ALLOW";
      break;
    case Envoy::Cilium::RuleVerdict::Deny:
      name = "DENY";
      break;
    case Envoy::Cilium::RuleVerdict::Pass:
      name = "PASS";
      break;
    default:
      name = "UNKNOWN";
      break;
    }
    return std::ranges::copy(name, ctx.out()).out;
  }
};

} // namespace fmt

namespace Envoy {
namespace Cilium {

// A specific version of a selector used in a policy. Each update yields a new instance.
class SelectorInstance : public VersionedNode<SelectorInstance>,
                         public absl::flat_hash_set<uint32_t> {};

// Read-only series of specific selector instances.
class NamedSelectorReadable : public VersionedReadable<SelectorInstance> {
public:
  explicit NamedSelectorReadable(const std::string& name) : name_(name) {}

  const std::string& name() const { return name_; }

private:
  std::string name_;
};

// Stable handle on a read-only selector for accessing specific versions of the selector.
using SelectorHandle = std::shared_ptr<const NamedSelectorReadable>;

// Writable series of selector versions for main-thread updates
using NamedSelectorValue = VersionedValue<SelectorInstance, NamedSelectorReadable>;

// Map of named selectors, keyed with xDS resource name
using SelectorMap = VersionedMap<std::string, SelectorInstance, NamedSelectorValue>;

// Immutable policies are shared across publications and destroyed on the main thread.
class Policy {
public:
  virtual ~Policy() {
    if (!Thread::MainThread::isMainOrTestThread()) {
      IS_ENVOY_BUG("Policy: Destructor executing in a worker thread, while "
                   "only main thread should destruct xDS resources");
    }
  }

  virtual const PortPolicy findPortPolicy(bool ingress, uint16_t port,
                                          SelectorVersion selector_version) const PURE;

  virtual bool allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
                       Http::RequestHeaderMap& headers, AccessLog::Entry& log_entry,
                       SelectorVersion selector_version) const {
    return findPortPolicy(ingress, port, selector_version)
        .allowed(proxy_id, remote_id, headers, log_entry);
  }

  virtual uint32_t getEndpointID() const PURE;

  virtual const IpAddressPair& getEndpointIPs() const PURE;

  virtual std::string string() const PURE;

  virtual void tlsWrapperMissingPolicyInc() const PURE;
};

const PortPolicy PolicyInstance::findPortPolicy(bool ingress, uint16_t port) const {
  return policy_.findPortPolicy(ingress, port, selector_version_);
}

bool PolicyInstance::allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id, uint16_t port,
                             Http::RequestHeaderMap& headers, AccessLog::Entry& log_entry) const {
  return policy_.allowed(ingress, proxy_id, remote_id, port, headers, log_entry, selector_version_);
}

bool PolicyInstance::allowed(bool ingress, uint16_t proxy_id, uint32_t remote_id,
                             absl::string_view sni, uint16_t port) const {
  return findPortPolicy(ingress, port).allowed(proxy_id, remote_id, sni);
}

uint32_t PolicyInstance::getEndpointID() const { return policy_.getEndpointID(); }

const IpAddressPair& PolicyInstance::getEndpointIPs() const { return policy_.getEndpointIPs(); }

std::string PolicyInstance::string() const { return policy_.string(); }

void PolicyInstance::tlsWrapperMissingPolicyInc() const { policy_.tlsWrapperMissingPolicyInc(); }

class PolicyImpl;

// Stable policy map, usually keyed with endpoint IP (IPv4 and IPv6).
using PolicyLookupMap = absl::flat_hash_map<std::string, std::shared_ptr<const PolicyImpl>>;

// One publication couples policy lookup with selector visibility. Selector-only updates share the
// immutable lookup map; readers never combine policies and selector versions from different
// updates.
struct PolicyMapSnapshot {
  std::shared_ptr<const PolicyLookupMap> policies;
  SelectorVersion selector_version;
  uint64_t stream_generation;
};

// variant wrapper for supported resource map keys for delta policy updates
// Delta xDS refers to removed resources by resource name, so we must have a map to
// locate the policy/selector to be removed.
class ResourceKey {
public:
  struct PolicyResourceEntry {
    std::shared_ptr<const PolicyImpl> policy;
  };

  // reference to a policy entry by name
  struct PolicyEndpointIpEntry {
    std::string policy_name;
  };

  struct SelectorResourceEntry {
    SelectorHandle handle;
  };

  static ResourceKey policyResource(const std::shared_ptr<const PolicyImpl>& policy) {
    return ResourceKey(PolicyResourceEntry{policy});
  }

  static ResourceKey policyEndpointIp(const std::string& name) {
    return ResourceKey(PolicyEndpointIpEntry{name});
  }

  static ResourceKey selectorResource(const SelectorHandle& handle) {
    return ResourceKey(SelectorResourceEntry{handle});
  }

  const PolicyResourceEntry* policyResourceEntry() const {
    return absl::get_if<PolicyResourceEntry>(&value_);
  }

  const SelectorResourceEntry* selectorResourceEntry() const {
    return absl::get_if<SelectorResourceEntry>(&value_);
  }

  const PolicyEndpointIpEntry* policyEndpointIpEntry() const {
    return absl::get_if<PolicyEndpointIpEntry>(&value_);
  }

  bool isPolicyEndpointIpEntry() const {
    return absl::holds_alternative<PolicyEndpointIpEntry>(value_);
  }

private:
  explicit ResourceKey(const PolicyResourceEntry& value) : value_(value) {}
  explicit ResourceKey(const PolicyEndpointIpEntry& value) : value_(value) {}
  explicit ResourceKey(const SelectorResourceEntry& value) : value_(value) {}

  absl::variant<PolicyResourceEntry, PolicyEndpointIpEntry, SelectorResourceEntry> value_;
};

// Map of Delta xDS resources for name collision and duplicate name detection.
class ResourceMap : public absl::flat_hash_map<std::string, ResourceKey> {
public:
  using absl::flat_hash_map<std::string, ResourceKey>::flat_hash_map;

  const ResourceKey* findEntry(const std::string& key) const {
    auto it = find(key);
    return it != end() ? &it->second : nullptr;
  }
};

// Main-thread staging directory. Workers only see the immutable snapshot published after all
// candidates have been processed; failed NPRDS replacements retain their accepted entries.
class ResourceMapOverlay {
public:
  ResourceMapOverlay() = default;
  explicit ResourceMapOverlay(const ResourceMap& base) : base_(&base) {}

  const ResourceKey* findEntry(const std::string& key) const {
    auto upsert_it = upserts_.find(key);
    if (upsert_it != upserts_.end()) {
      return &upsert_it->second;
    }
    if (removed_.contains(key)) {
      return nullptr;
    }
    return base_ ? base_->findEntry(key) : nullptr;
  }

  std::string describeExistingResourceKey(const std::string& key) const;

  SelectorHandle getSelectorHandleOrThrow(const std::string& selector) const {
    const auto* entry = findEntry(selector);
    if (entry == nullptr) {
      throw EnvoyException(fmt::format(
          "NetworkPolicyResource rule references missing selector resource '{}'", selector));
    }
    const auto* selector_entry = entry->selectorResourceEntry();
    if (selector_entry == nullptr || selector_entry->handle == nullptr) {
      throw EnvoyException(fmt::format(
          "NetworkPolicyResource rule references non-selector resource '{}'", selector));
    }
    return selector_entry->handle;
  }

  bool emplace(const std::string& key, ResourceKey&& value) {
    if (findEntry(key)) {
      return false;
    }
    removed_.erase(key);
    return upserts_.emplace(key, std::move(value)).second;
  }

  void put(const std::string& key, ResourceKey value) {
    removed_.erase(key);
    upserts_.insert_or_assign(key, std::move(value));
  }

  void erase(const std::string& key) {
    upserts_.erase(key);
    if (base_ && base_->find(key) != base_->end()) {
      removed_.insert(key);
    } else {
      removed_.erase(key);
    }
  }

  bool erasePolicyResourceIfPresent(const std::string& resource_name) {
    const auto* entry = findEntry(resource_name);
    if (entry == nullptr) {
      return false;
    }
    const auto* policy_entry = entry->policyResourceEntry();
    if (policy_entry == nullptr) {
      return false;
    }
    erasePolicyResource(resource_name, policy_entry->policy);
    return true;
  }

  void erasePolicyResource(const std::string& resource_name,
                           const std::shared_ptr<const PolicyImpl>& policy);

  PolicyLookupMap toPolicyLookupMap() const;

  void applyTo(ResourceMap& map) && {
    if (!upserts_.empty()) {
      map.reserve(map.size() + upserts_.size());
    }
    for (const auto& key : removed_) {
      map.erase(key);
    }
    for (auto& [key, value] : upserts_) {
      map.insert_or_assign(std::move(key), std::move(value));
    }
  }

private:
  template <class Visitor> void forEachEntry(Visitor visitor) const {
    if (base_) {
      for (const auto& [key, value] : *base_) {
        if (!removed_.contains(key) && !upserts_.contains(key)) {
          visitor(key, value);
        }
      }
    }
    for (const auto& [key, value] : upserts_) {
      visitor(key, value);
    }
  }

  std::pair<const std::string&, std::shared_ptr<const PolicyImpl>>
  findPolicyByEndpointIp(const std::string& endpoint_ip) const;

  const ResourceMap* base_{};
  absl::flat_hash_set<std::string> removed_;
  absl::flat_hash_map<std::string, ResourceKey> upserts_;
};

// helper for validating resource names.
void validateResourceName(const std::string& resource_name, absl::string_view subject) {
  if (resource_name.empty()) {
    throw EnvoyException(fmt::format("{} must not be empty", subject));
  }
  if (std::ranges::any_of(resource_name, [](unsigned char c) { return absl::ascii_isspace(c); })) {
    throw EnvoyException(
        fmt::format("{} '{}' must not contain whitespace", subject, resource_name));
  }
}

class NetworkPolicyMapImpl : public ManagedGrpcSubscription {
public:
  friend class PortNetworkPolicyRule;
  friend class NprdsUpdate;
  NetworkPolicyMapImpl(Server::Configuration::FactoryContext& context,
                       const envoy::config::core::v3::ConfigSource& config_source, bool subscribe,
                       bool policy_secret_cache_enabled);
  ~NetworkPolicyMapImpl() override;

  // Config::SubscriptionCallbacks
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) override;

  std::shared_ptr<NetworkPolicyMapImpl> sharedFromThis() {
    return std::static_pointer_cast<NetworkPolicyMapImpl>(
        ManagedGrpcSubscription::shared_from_this());
  }

  Server::Configuration::TransportSocketFactoryContext& transportFactoryContext() const {
    return *transport_factory_context_;
  }

  DownstreamTLSContextSharedPtr getDownstreamTlsContext(const cilium::TLSContext& config) const {
    return policy_secret_cache_.getOrCreateDownstream(config);
  }

  UpstreamTLSContextSharedPtr getUpstreamTlsContext(const cilium::TLSContext& config) const {
    return policy_secret_cache_.getOrCreateUpstream(config);
  }

  SecretWatcherSharedPtr getSecretWatcher(const std::string& sds_name) const {
    return policy_secret_cache_.getOrCreateSecretWatcher(sds_name);
  }

  Regex::Engine& regexEngine() const { return context_.regexEngine(); }

  void tlsWrapperMissingPolicyInc() const { stats_.tls_wrapper_missing_policy_.inc(); }

protected:
  // run the given function after all the threads have scheduled
  void runAfterAllThreads(std::function<void()> cb) const {
    // We can guarantee the callback 'cb' runs in the main thread after all worker threads have
    // entered their event loop, and thus relinquished all state, such as policy lookup results that
    // were stored in their call stack, by posting and empty function to their event queues and
    // waiting until all of them have returned, as managed by 'runOnAllWorkerThreads'.
    context_.threadLocal().runOnAllWorkerThreads([]() {}, cb);
  }

  void reopenIpcache();

  void validatePolicy(const std::string& resource_name, const cilium::NetworkPolicy& config,
                      const std::string& version_info);

  std::shared_ptr<const PolicyImpl>
  createOrReusePolicy(const std::string& resource_name, const cilium::NetworkPolicy& config,
                      const ResourceMap& resource_map, bool is_new_stream,
                      const ResourceMapOverlay* pending_resource_map) const;

  absl::Status onNpdsConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                                  const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                                  const std::string& version_info, bool sotw);
  absl::Status onNprdsConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                                   const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                                   const std::string& version_info, bool sotw);

  void publishPolicyUpdate(ResourceMapOverlay&& pending_resource_map, uint64_t stream_generation,
                           bool rebuild_policy_map);

private:
  // Published snapshots are immutable. Workers borrow them until their next event-loop turn;
  // retirement and selector reclamation run on the main thread after worker grace periods.
  const PolicyMapSnapshot* load() const { return map_ptr_.load(std::memory_order_acquire); }
  void store(const PolicyMapSnapshot* map) { map_ptr_.store(map, std::memory_order_release); }
  const PolicyMapSnapshot* exchange(const PolicyMapSnapshot* map) {
    return map_ptr_.exchange(map, std::memory_order_release);
  }

  const PolicyInstance getPolicyInstance(const std::string& endpoint_policy_name,
                                         bool allow_egress) const;
  std::shared_ptr<const Policy> getPolicyShared(const std::string& endpoint_policy_name) const;
  void removeInitManager();

  static uint64_t instance_id_;

  void scheduleSelectorDeferredDeletion(DeferredDeletion<SelectorInstance>&& deferred);
  void scheduleSelectorGCAndDeferredDeletion(uint64_t published_version,
                                             const PolicyMapSnapshot* old_policy_map,
                                             bool policies_changed);

  Server::Configuration::ServerFactoryContext& context_;

  std::atomic<const PolicyMapSnapshot*> map_ptr_;
  SelectorMap selector_map_;
  const ResourceMap empty_resource_map_;
  ResourceMap resource_map_;
  Stats::ScopeSharedPtr policy_stats_scope_;

  // init target which starts gRPC subscription
  Init::TargetImpl init_target_;
  std::shared_ptr<Server::Configuration::TransportSocketFactoryContextImpl>
      transport_factory_context_;
  // Declared after transport_factory_context_ so that the cache, which retains a shared reference
  // to the factory context, is destroyed first.
  PolicySecretCache policy_secret_cache_;
  // Between policy updates, keep a dormant init manager installed so unexpected late init-target
  // registrations do not hit the listener's already-initialized manager. If it accumulates targets
  // while parked, log and rotate it out before making it active again.
  std::unique_ptr<Init::ManagerImpl> parked_init_manager_;

  ProtobufTypes::MessagePtr dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher);
  Server::ConfigTracker::EntryOwnerPtr config_tracker_entry_;

protected:
  friend class NetworkPolicyMap;

  PolicyStats stats_;
};

uint64_t NetworkPolicyMapImpl::instance_id_ = 0;

IpAddressPair::IpAddressPair(const cilium::NetworkPolicy& proto) {
  for (const auto& ip_addr : proto.endpoint_ips()) {
    auto ip = Network::Utility::parseInternetAddressNoThrow(ip_addr);
    if (ip) {
      switch (ip->ip()->version()) {
      case Network::Address::IpVersion::v4:
        ipv4_ = std::move(ip);
        break;
      case Network::Address::IpVersion::v6:
        ipv6_ = std::move(ip);
        break;
      }
    }
  }
}

class HeaderMatch : public Logger::Loggable<Logger::Id::config> {
public:
  HeaderMatch(const NetworkPolicyMapImpl& parent, const cilium::HeaderMatch& config)
      : name_(config.name()), value_(config.value()), match_action_(config.match_action()),
        mismatch_action_(config.mismatch_action()) {
    if (!config.value_sds_secret().empty()) {
      secret_ = parent.getSecretWatcher(config.value_sds_secret());
    }
  }

  void logRejected(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
    log_entry.addRejected(name_.get(), !secret_ ? value : "[redacted]");
  }

  void logMissing(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
    log_entry.addMissing(name_.get(), !secret_ ? value : "[redacted]");
  }

  // Returns 'true' if matching can continue
  bool allowed(Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
    bool matches = false;
    const std::string* match_value = &value_;
    const auto header_value = Http::HeaderUtility::getAllOfHeaderAsString(headers, name_);

    // Get secret value?
    if (secret_) {
      auto* secret_value = secret_->value();
      if (secret_value) {
        match_value = secret_value;
      } else if (value_.empty()) {
        // fail if secret has no value and the inline value to match is also empty
        ENVOY_LOG(info, "Cilium HeaderMatch missing SDS secret value for header {}", name_);
        return false;
      }
    }

    // Perform presence match if the value to match is empty
    bool is_present_match = match_value->empty();
    if (is_present_match) {
      matches = header_value.result().has_value();
    } else if (header_value.result().has_value()) {
      const absl::string_view val = header_value.result().value();
      if (val.length() == match_value->length()) {
        // Use constant time comparison for security reason
        matches = CRYPTO_memcmp(val.data(), match_value->data(), match_value->length()) == 0;
      }
    }

    if (matches) {
      // Match action
      switch (match_action_) {
      case cilium::HeaderMatch::CONTINUE_ON_MATCH:
        return true;
      case cilium::HeaderMatch::FAIL_ON_MATCH:
      default: // fail closed if unknown action
        logRejected(log_entry, *match_value);
        return false;
      case cilium::HeaderMatch::DELETE_ON_MATCH:
        logRejected(log_entry, *match_value);
        headers.remove(name_);
        return true;
      }
    } else {
      // Mismatch action
      switch (mismatch_action_) {
      case cilium::HeaderMatch::FAIL_ON_MISMATCH:
      default:
        logMissing(log_entry, *match_value);
        return false;
      case cilium::HeaderMatch::CONTINUE_ON_MISMATCH:
        logMissing(log_entry, *match_value);
        return true;
      case cilium::HeaderMatch::ADD_ON_MISMATCH:
        headers.addCopy(name_, *match_value);
        logMissing(log_entry, *match_value);
        return true;
      case cilium::HeaderMatch::DELETE_ON_MISMATCH:
        if (is_present_match) {
          // presence match failed, nothing to do
          return true;
        }
        if (!header_value.result().has_value()) {
          return true; // nothing to remove
        }

        // Log the incorrect value before removing its backing header storage.
        logRejected(log_entry, header_value.result().value());
        headers.remove(name_);
        return true;
      case cilium::HeaderMatch::REPLACE_ON_MISMATCH:
        // Log the wrong value as rejected, if the header existed with a wrong value
        if (header_value.result().has_value()) {
          logRejected(log_entry, header_value.result().value());
        }
        // Set the expected value
        headers.setCopy(name_, *match_value);
        // Log the expected value as missing
        logMissing(log_entry, *match_value);
        return true;
      }
    }
    IS_ENVOY_BUG("HeaderMatch reached unreachable return");
    return false;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- name: \"").append(name_.get()).append("\"\n");
    if (!value_.empty()) {
      res.append(indent, ' ').append("value: \"").append(value_).append("\"\n");
    }
    if (secret_) {
      res.append(indent, ' ').append("secret: \"").append(secret_->name()).append("\"\n");
    }
    const char* match_actions[] = {"CONTINUE", "FAIL", "DELETE", "UNKNOWN"};
    res.append(indent, ' ')
        .append("match_action: ")
        .append(match_actions[std::max(int(match_action_), 3)])
        .append("\n");

    const char* mismatch_actions[] = {"FAIL", "CONTINUE", "ADD", "DELETE", "REPLACE", "UNKNOWN"};
    res.append(indent, ' ')
        .append("mismatch_action: ")
        .append(mismatch_actions[std::max(int(mismatch_action_), 5)])
        .append("\n");
  }

  const Http::LowerCaseString name_;
  std::string value_;
  cilium::HeaderMatch::MatchAction match_action_;
  cilium::HeaderMatch::MismatchAction mismatch_action_;
  // Shared state contains only the SDS resource name and its atomically published value. Header
  // matching behavior and the optional inline fallback remain local to this HeaderMatch.
  SecretWatcherSharedPtr secret_;
};

class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  HttpNetworkPolicyRule(const NetworkPolicyMapImpl& parent,
                        const cilium::HttpNetworkPolicyRule& rule) {
    ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
    headers_.reserve(rule.headers().size());
    for (const auto& header : rule.headers()) {
      headers_.emplace_back(Http::HeaderUtility::createHeaderData(
          header, parent.transportFactoryContext().serverFactoryContext()));

      auto value = header.has_range_match()   ? fmt::format("[{}-{})", header.range_match().start(),
                                                            header.range_match().end())
                   : header.has_exact_match() ? "<VALUE>"
                   : header.has_present_match()    ? "<PRESENT>"
                   : header.has_safe_regex_match() ? "<REGEX>"
                                                   : "<UNKNOWN>";
      ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={}", header.name(), value);
    }
    header_matches_.reserve(rule.header_matches().size());
    for (const auto& config : rule.header_matches()) {
      header_matches_.emplace_back(parent, config);
      const auto& header_match = header_matches_.back();
      ENVOY_LOG(trace,
                "Cilium L7 HttpNetworkPolicyRule(): HeaderMatch {}={} (match: {}, mismatch: {})",
                header_match.name_.get(),
                header_match.secret_ ? fmt::format("<SECRET {}>", header_match.secret_->name())
                : !header_match.value_.empty() ? header_match.value_
                                               : "<PRESENT>",
                cilium::HeaderMatch::MatchAction_Name(header_match.match_action_),
                cilium::HeaderMatch::MismatchAction_Name(header_match.mismatch_action_));
    }
  }

  bool allowed(const Envoy::Http::RequestHeaderMap& headers) const {
    // Empty set matches any headers.
    return Http::HeaderUtility::matchHeaders(headers, headers_);
  }

  // Should only be called after 'allowed' returns 'true'.
  // Returns 'true' if matching can continue
  bool headerMatches(Envoy::Http::RequestHeaderMap& headers,
                     Cilium::AccessLog::Entry& log_entry) const {
    bool accepted = true;
    for (const auto& header_match : header_matches_) {
      if (!header_match.allowed(headers, log_entry)) {
        accepted = false;
      }
    }
    return accepted;
  }

  void toString(int indent, std::string& res) const {
    bool first = true;
    if (!headers_.empty()) {
      if (first) {
        first = false;
        res.append(indent - 2, ' ').append("- ");
      } else {
        res.append(indent, ' ');
      }
      res.append("headers:\n");
      for (auto& h : headers_) {
        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataBaseImpl*>(h.get())) {
          res.append(indent, ' ').append("- name: \"").append(v->name_).append("\"\n");
        }

        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataExactMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("value: \"").append(v->expected_value_).append("\"\n");
        } else if (dynamic_cast<Http::HeaderUtility::HeaderDataRegexMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("regex: ").append("<hidden>\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataRangeMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("range: ")
              .append(fmt::format("[{}-{})\n", v->range_start_, v->range_end_));
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataPresentMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("present: ")
              .append(v->present_ ? "true\n" : "false\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataPrefixMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("prefix: \"").append(v->prefix_).append("\"\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataSuffixMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("suffix: \"").append(v->suffix_).append("\"\n");
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataContainsMatch*>(h.get())) {
          res.append(indent + 2, ' ')
              .append("contains: \"")
              .append(v->expected_substr_)
              .append("\"\n");
        } else if (dynamic_cast<Http::HeaderUtility::HeaderDataStringMatch*>(h.get())) {
          res.append(indent + 2, ' ').append("string_match: ").append("<hidden>\n");
        }

        if (const auto v = dynamic_cast<Http::HeaderUtility::HeaderDataBaseImpl*>(h.get())) {
          if (v->invert_match_) {
            res.append(indent + 2, ' ').append("invert_match: true\n");
          }

          if (v->treat_missing_as_empty_) {
            res.append(indent + 2, ' ').append("treat_missing_as_empty: true\n");
          }
        }
      }
    }
    if (!header_matches_.empty()) {
      if (first) {
        // first = false; // not used after, so no need to update
        res.append(indent - 2, ' ').append("- ");
      } else {
        res.append(indent, ' ');
      }
      res.append("header_matches:\n");
      for (auto& hm : header_matches_) {
        hm.toString(indent + 2, res);
      }
    }
  }

  std::vector<Http::HeaderUtility::HeaderDataPtr> headers_; // Allowed if empty.
  std::vector<HeaderMatch> header_matches_;
};

// Constructs SniPattern with the provided regex engine for input match pattern.
SniPattern::SniPattern(const Regex::Engine& engine, absl::string_view sni) {
  if (!isValid(sni)) {
    throw EnvoyException(fmt::format("SniPattern: Unsupported match pattern {}", sni));
  }

  // Only regex characters supported in valid match pattern is '*'. If not present, pattern
  // can be reduced to explicit full match.
  if (!absl::StrContains(sni, '*')) {
    match_name_ = absl::AsciiStrToLower(sni);
    return;
  }

  std::string regex_expr;
  if (sni == "*") {
    // For a full wildcard match pattern replace with static wildcard pattern for DNS characters.
    regex_expr = "[-a-z0-9_]+([.][-a-z0-9_]+)*";
  } else {
    // NOTE: We already validated that the provided pattern cannot have more than 2 consecutive
    // wildcard specifier('*'). This simplifies the regex replacement by isolating '**' and '*'
    // specifiers.
    regex_expr = absl::StrReplaceAll(
        absl::AsciiStrToLower(sni),
        {
            // Convert '.' to regex literal '[.]'
            {".", "[.]"},

            // '**' expands to regex for multilevel subdomain match.
            // The replaced regex pattern matches one or more entire DNS labels, for example:
            // * <dns-label>
            // * <dns-label-1>.<dns-label-2>.<dns-label-3>
            {"**", "[-a-z0-9_]+([.][-a-z0-9_]+){0,}"},

            // Replace wildcard specifier '*' with regex for any number of valid DNS characters
            // within subdomain boundry(doesn't include '.' literal).
            {"*", "[-a-z0-9_]{0,}"},
        });
  }

  auto regex_matcher = engine.matcher(regex_expr);
  if (!regex_matcher.ok()) {
    throw EnvoyException(fmt::format("SniPattern: Failed to create pattern for SNI {} - {}", sni,
                                     regex_matcher.status().ToString()));
  }

  matcher_ = std::move(regex_matcher.value());
}

class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRule()
      : name_("default allow rule"), verdict_(RuleVerdict::Allow), proxy_id_(0), precedence_(0),
        tier_last_precedence_(0), pass_index_(0) {}

  PortNetworkPolicyRule(const NetworkPolicyMapImpl& parent,
                        const cilium::PortNetworkPolicyRule& rule,
                        const ResourceMapOverlay* resource_map)
      : name_(rule.name()),
        verdict_(rule.pass_precedence() ? RuleVerdict::Pass
                                        : (rule.deny() ? RuleVerdict::Deny : RuleVerdict::Allow)),
        proxy_id_(uint16_t(rule.proxy_id())), precedence_(rule.precedence()),
        tier_last_precedence_(rule.pass_precedence()), pass_index_(0) {
    if (tier_last_precedence_ > precedence_) {
      throw EnvoyException(
          fmt::format("PortNetworkPolicyRule: pass_precedence {} must be lower than precedence {}",
                      tier_last_precedence_, precedence_));
    }
    if (resource_map) {
      if (rule.remote_policies_size()) {
        throw EnvoyException(
            "NetworkPolicyResource rule must use selectors instead of remote_policies");
      }
      selectors_.reserve(rule.selectors_size());
      for (const auto& selector : rule.selectors()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} selector {} by rule: {}", verdict_,
                  selector, name_);
        selectors_.emplace_back(resource_map->getSelectorHandleOrThrow(selector));
      }
    } else {
      if (rule.selectors_size()) {
        throw EnvoyException("NetworkPolicy rule must not use selectors");
      }
      for (const auto remote : rule.remote_policies()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} remote {} by rule: {}", verdict_,
                  remote, name_);
        remotes_.emplace(remote);
      }
    }
    if (rule.has_downstream_tls_context()) {
      server_context_ = parent.getDownstreamTlsContext(rule.downstream_tls_context());
    }
    if (rule.has_upstream_tls_context()) {
      client_context_ = parent.getUpstreamTlsContext(rule.upstream_tls_context());
    }
    for (const auto& sni : rule.server_names()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} SNI {} by rule {}", verdict_, sni,
                name_);
      allowed_snis_.emplace_back(parent.regexEngine(), sni);
    }
    if (rule.has_http_rules()) {
      http_rules_ = std::make_shared<std::vector<HttpNetworkPolicyRule>>();
      for (const auto& http_rule : rule.http_rules().http_rules()) {
        if (http_rule.header_matches_size() > 0) {
          has_headermatches_ = true;
        }
        http_rules_->emplace_back(parent, http_rule);
      }
    }
  }

  bool isRemoteWildcard() const { return remotes_.empty() && selectors_.empty(); }

  bool matchesRemoteId(uint32_t remote_id, const SelectorVersion selector_version) const {
    if (isRemoteWildcard()) {
      return true;
    }
    if (!remotes_.empty()) {
      return remotes_.contains(remote_id);
    }

    for (const auto& selector : selectors_) {
      const auto resolved_selector = selector->get(selector_version);
      if (resolved_selector &&
          (resolved_selector->contains(remote_id) || resolved_selector->contains(0))) {
        return true;
      }
    }
    return false;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         const SelectorVersion selector_version) const {
    // proxy_id must match if we have any.
    if (proxy_id_ && proxy_id != proxy_id_) {
      return RuleVerdict::None;
    }
    // Remote ID must match if we have any.
    if (!matchesRemoteId(remote_id, selector_version)) {
      return RuleVerdict::None; // no verdict
    }
    ASSERT(verdict_ != RuleVerdict::None, "rule must have a verdict");
    return verdict_;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                         const SelectorVersion selector_version) const {
    // sni must match if we have any
    if (!allowed_snis_.empty() &&
        (sni.empty() || std::ranges::none_of(allowed_snis_, [&](const auto& pattern) {
           return pattern.matches(sni);
         }))) {
      return RuleVerdict::None;
    }
    return getVerdict(proxy_id, remote_id, selector_version);
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry,
                         const SelectorVersion selector_version) const {
    auto verdict = getVerdict(proxy_id, remote_id, selector_version);
    if ((verdict == RuleVerdict::None || verdict == RuleVerdict::Deny) || !hasHttpRules()) {
      return verdict;
    }
    if (!has_headermatches_) {
      if (std::ranges::any_of(*http_rules_, [&](auto& r) { return r.allowed(headers); })) {
        return verdict;
      }
      return RuleVerdict::None;
    }

    // Evaluate all rules to run all the header actions,
    // and remember if any of them matched
    bool header_matched = false;
    for (const auto& rule : *http_rules_) {
      if (rule.allowed(headers)) {
        if (rule.headerMatches(headers, log_entry)) {
          header_matched = true;
        }
      }
    }
    return (header_matched) ? verdict : RuleVerdict::None;
  }

  // getServerTlsContext returns true if the rule has server TLS context that was passed to the
  // caller via the reference arguments.
  bool getServerTlsContext(Ssl::ContextSharedPtr& tls_context,
                           const Ssl::ContextConfig*& config) const {
    if (server_context_) {
      tls_context = server_context_->getTlsContext();
      config = &server_context_->getTlsContextConfig();
      return true;
    }
    return false;
  }

  // getClientTlsContext returns true if the rule has client TLS context that was passed to the
  // caller via the reference arguments.
  bool getClientTlsContext(Ssl::ContextSharedPtr& tls_context,
                           const Ssl::ContextConfig*& config) const {
    if (client_context_) {
      tls_context = client_context_->getTlsContext();
      config = &client_context_->getTlsContextConfig();
      return true;
    }
    return false;
  }

  void toString(int indent, std::string& res) const {
    if (!selectors_.empty()) {
      res.append(indent - 2, ' ').append("- selectors: [");
      std::vector<std::string> quoted_selectors;
      quoted_selectors.reserve(selectors_.size());
      for (const auto& selector : selectors_) {
        quoted_selectors.emplace_back(fmt::format("\"{}\"", selector->name()));
      }
      res.append(fmt::format("{}", fmt::join(quoted_selectors, ",")));
    } else {
      res.append(indent - 2, ' ').append("- remotes: [");
      res.append(fmt::format("{}", fmt::join(remotes_, ",")));
    }
    res.append("]\n");

    if (!name_.empty()) {
      res.append(indent, ' ').append("name: \"").append(name_).append("\"\n");
    }
    if (verdict_ == RuleVerdict::Deny) {
      res.append(indent, ' ').append("deny: true\n");
    }
    if (precedence_) {
      res.append(indent, ' ').append(fmt::format("precedence: {}\n", precedence_));
    }
    if (tier_last_precedence_) {
      res.append(indent, ' ')
          .append(fmt::format("tier_last_precedence: {}\n", tier_last_precedence_));
    }
    if (proxy_id_) {
      res.append(indent, ' ').append(fmt::format("proxy_id: {}\n", proxy_id_));
    }

    if (!allowed_snis_.empty()) {
      res.append(indent, ' ').append("allowed_snis: [");
      int count = 0;
      for (auto& sni : allowed_snis_) {
        if (count++ > 0) {
          res.append(",");
        }
        sni.toString(res);
      }
      res.append("]\n");
    }

    if (hasHttpRules()) {
      res.append(indent, ' ').append("http_rules:\n");
      for (auto& rule : *http_rules_) {
        rule.toString(indent + 2, res);
      }
    }
  }

  bool hasHttpRules() const { return http_rules_ && !http_rules_->empty(); }

  const std::string name_;
  DownstreamTLSContextSharedPtr server_context_;
  UpstreamTLSContextSharedPtr client_context_;
  bool has_headermatches_{false};
  const RuleVerdict verdict_;
  const uint16_t proxy_id_;
  const uint32_t precedence_;
  const uint32_t tier_last_precedence_;
  uint32_t pass_index_;
  absl::btree_set<uint32_t> remotes_;
  std::vector<SelectorHandle> selectors_;

  std::vector<SniPattern> allowed_snis_; // All SNIs allowed if empty.
  std::shared_ptr<std::vector<HttpNetworkPolicyRule>>
      http_rules_; // Allowed if empty, but remote is checked first.
};
using PortNetworkPolicyRuleSharedPtr = std::shared_ptr<PortNetworkPolicyRule>;
using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRules() = default;

  ~PortNetworkPolicyRules() {
    if (!Thread::MainThread::isMainOrTestThread()) {
      IS_ENVOY_BUG("PortNetworkPolicyRules: Destructor executing in a worker thread, while "
                   "only main thread should destruct xDS resources");
    }
  }

  void clear() {
    rules_.clear();
    can_short_circuit_ = true;
    has_pass_rules_ = false;
  }

  // Move assignment operator
  PortNetworkPolicyRules& operator=(PortNetworkPolicyRules&& other) noexcept = default;

  // Move constructor
  PortNetworkPolicyRules(PortNetworkPolicyRules&& other) noexcept = default;

  // Copy constructors
  PortNetworkPolicyRules& operator=(const PortNetworkPolicyRules&) = default;
  PortNetworkPolicyRules(const PortNetworkPolicyRules&) = default;

  void updateFor(const PortNetworkPolicyRuleConstSharedPtr& rule) {
    if (rule->has_headermatches_) {
      can_short_circuit_ = false;
    }
    if (rule->tier_last_precedence_) {
      has_pass_rules_ = true;
    }
  }

  void addDefaultAllowRule() { rules_.emplace_back(std::make_shared<PortNetworkPolicyRule>()); }

  // append merges 'rules' to 'rules_' by placing the new 'rules' to the end of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of empty rules.
  void append(const NetworkPolicyMapImpl& parent,
              const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules,
              const ResourceMapOverlay* selector_resource_map) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      // add an explicit allow-all rule to keep the combined semantics
      addDefaultAllowRule();
    }
    for (const auto& it : rules) {
      rules_.emplace_back(
          std::make_shared<PortNetworkPolicyRule>(parent, it, selector_resource_map));
      updateFor(rules_.back());
    }
    initialized_ = true;
  }

  // prepend merges 'rules' to 'rules_' by placing the new 'rules' to the front of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of an empty rules.
  void prepend(const NetworkPolicyMapImpl& parent,
               const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules,
               const ResourceMapOverlay* resource_map) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      // add an explicit allow-all rule to keep the combined semantics
      rules_.emplace(rules_.begin(), std::make_shared<PortNetworkPolicyRule>());
    }
    for (const auto& it : rules) {
      rules_.emplace(rules_.begin(),
                     std::make_shared<PortNetworkPolicyRule>(parent, it, resource_map));
      updateFor(rules_.front());
    }
    initialized_ = true;
  }

  // appendRules merges all rules from 'rules' to the end of 'rules_'.
  // First call marks 'rules_' as initialized. Of further calls, if either is empty,
  // we must add a default allow rule to retain the semantics of the combined rules.
  void appendRules(const std::vector<PortNetworkPolicyRuleConstSharedPtr>& rules) {
    if (initialized_ && rules.empty() != rules_.empty()) {
      addDefaultAllowRule();
    }
    for (auto& rule : rules) {
      rules_.insert(rules_.end(), rule);
      updateFor(rule);
    }
    initialized_ = true;
  }

  // Sort by descending precedence. Within the same precedence, deny rules come first,
  // then allow rules, and pass rules last. This lets runtime pass handling jump
  // immediately, as any same-precedence allow/deny verdict has already been seen.
  void sort() {
    std::stable_sort(rules_.begin(), rules_.end(),
                     [](const PortNetworkPolicyRuleConstSharedPtr& a,
                        const PortNetworkPolicyRuleConstSharedPtr& b) {
                       return (a->precedence_ > b->precedence_) ||
                              (a->precedence_ == b->precedence_ && a->verdict_ > b->verdict_);
                     });
  }

  void prepareRuntimePasses() {
    if (!has_pass_rules_) {
      return;
    }

    uint32_t pass_precedence = 0;
    for (uint32_t idx = 0; idx < rules_.size(); idx++) {
      if (rules_[idx]->tier_last_precedence_ == 0) {
        continue;
      }

      if (rules_[idx].use_count() > 1) {
        // Pass continuation index is specific to this ordered rule set, so shared pass
        // rules must be cloned before storing the computed continuation on the rule.
        rules_[idx] = std::make_shared<PortNetworkPolicyRule>(*rules_[idx]);
      }
      auto& rule = const_cast<PortNetworkPolicyRule&>(*rules_[idx]);

      if (pass_precedence && rule.precedence_ < pass_precedence) {
        pass_precedence = 0;
      }

      if (pass_precedence && rule.tier_last_precedence_ != pass_precedence) {
        throw EnvoyException(fmt::format("PortNetworkPolicy: Inconsistent pass precedence {} != {}",
                                         rule.tier_last_precedence_, pass_precedence));
      }
      pass_precedence = rule.tier_last_precedence_;

      uint32_t pass_index = idx + 1;
      while (pass_index < rules_.size() && rules_[pass_index]->precedence_ >= pass_precedence) {
        pass_index++;
      }
      rule.pass_index_ = pass_index;
    }
  }

  bool empty() const { return rules_.empty(); }

  template <typename F> RuleVerdict forEachRule(bool can_short_circuit, F&& func) const {
    RuleVerdict verdict = RuleVerdict::None;
    uint32_t verdict_precedence = 0;

    // Uninitialized rules match nothing
    ASSERT(initialized_, "uninitialized rules");
    if (!initialized_) {
      return verdict;
    }

    // Empty set matches any payload from anyone
    if (empty()) {
      return RuleVerdict::Allow;
    }

    for (uint32_t idx = 0; idx < rules_.size();) {
      const auto& rule = rules_[idx];

      // lower precedence rules are skipped if there is a verdict
      if (verdict != RuleVerdict::None && rule->precedence_ < verdict_precedence) {
        break;
      }
      auto rule_verdict = func(*rule);
      if (rule_verdict == RuleVerdict::Pass) {
        ASSERT(rule->pass_index_, "matching pass rule must have a continuation index");
        if (verdict == RuleVerdict::None || verdict_precedence < rule->precedence_) {
          idx = rule->pass_index_;
          continue;
        }
      } else if (rule_verdict != RuleVerdict::None) {
        verdict = rule_verdict;
        verdict_precedence = rule->precedence_;

        // Short-circuit on the first deny or on first allow if no rules have HeaderMatches
        if (rule_verdict == RuleVerdict::Deny || can_short_circuit) {
          return verdict;
        }
      }
      idx++;
    }
    return verdict;
  }

  // forEachRulePred return a RuleVerdict by scanning through all rules, getting the verdict for
  // each rule and checking if the predicate matches. Returns RuleVerdict::Allow if any rule allows
  // the traffic, even if the predicate returns false. Stops as soon as the first rule returns
  // 'true' for the predicate.
  // This is used to the applicable TLS context from the rules, if any. Note that in this use 'pred'
  // has side effects, but it is idempotent.
  template <typename F, typename P> RuleVerdict forEachRulePred(F&& get_verdict, P&& pred) const {
    RuleVerdict verdict = RuleVerdict::None;
    uint32_t verdict_precedence = 0;

    // Uninitialized rules match nothing
    ASSERT(initialized_, "uninitialized rules");
    if (!initialized_) {
      return verdict;
    }

    // Empty set matches any payload from anyone
    if (empty()) {
      return RuleVerdict::Allow;
    }

    for (uint32_t idx = 0; idx < rules_.size();) {
      const auto& rule = rules_[idx];

      auto rule_verdict = get_verdict(*rule);
      switch (rule_verdict) {
      case RuleVerdict::Pass:
        ASSERT(rule->pass_index_, "matching pass rule must have a continuation index");
        if (verdict == RuleVerdict::None || verdict_precedence < rule->precedence_) {
          idx = rule->pass_index_;
          continue;
        }
        break;
      case RuleVerdict::Deny:
        // return higher precedence allow verdict if any.
        if (verdict != RuleVerdict::None && verdict_precedence > rule->precedence_) {
          return verdict;
        }
        return rule_verdict;
      case RuleVerdict::Allow:
        if (pred(*rule)) {
          // Return after the first allow verdict that fulfills the predicate
          return rule_verdict;
        }
        // store highest precedence allow verdict that does not fulfill the predicate
        if (verdict == RuleVerdict::None) {
          verdict = rule_verdict;
          verdict_precedence = rule->precedence_;
        }
        break;
      case RuleVerdict::None:
        break;
      }
      idx++;
    }
    return verdict;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry,
                         const SelectorVersion selector_version) const {
    auto verdict = forEachRule(can_short_circuit_, [&](const auto& rule) {
      return rule.getVerdict(proxy_id, remote_id, headers, log_entry, selector_version);
    });

    ENVOY_LOG(trace,
              "Cilium L7 PortNetworkPolicyRules(proxy_id: {}, remote_id: {}, headers: {}): {}",
              proxy_id, remote_id, headers, verdict);
    return verdict;
  }

  RuleVerdict getVerdict(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                         const SelectorVersion selector_version) const {
    auto verdict = forEachRule(true, [&](const auto& rule) {
      return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
    });

    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(proxy_id: {}, remote_id: {}, sni: {}): {}",
              proxy_id, remote_id, sni, verdict);
    return verdict;
  }

  RuleVerdict getServerTlsContext(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                                  Ssl::ContextSharedPtr& tls_ctx, const Ssl::ContextConfig*& config,
                                  const SelectorVersion selector_version) const {
    tls_ctx = nullptr;
    return forEachRulePred(
        [&](const auto& rule) {
          return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
        },
        [&](const auto& rule) { return rule.getServerTlsContext(tls_ctx, config); });
  }

  RuleVerdict getClientTlsContext(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni,
                                  Ssl::ContextSharedPtr& tls_ctx, const Ssl::ContextConfig*& config,
                                  const SelectorVersion selector_version) const {
    tls_ctx = nullptr;
    return forEachRulePred(
        [&](const auto& rule) {
          return rule.getVerdict(proxy_id, remote_id, sni, selector_version);
        },
        [&](const auto& rule) { return rule.getClientTlsContext(tls_ctx, config); });
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- rules:\n");
    for (const auto& rule : rules_) {
      rule->toString(indent + 2, res);
    }
    if (!can_short_circuit_) {
      res.append(indent, ' ').append(fmt::format("can_short_circuit: false\n"));
    }
  }

  bool hasHttpRules() const {
    for (const auto& rule : rules_) {
      if (rule->hasHttpRules()) {
        return true;
      }
    }
    return false;
  }

  bool hasOnlyPassRules() const {
    return !rules_.empty() &&
           std::ranges::all_of(rules_, [](const auto& rule) { return rule->pass_index_ != 0; });
  }

  // ordered set of rules as a sorted vector
  std::vector<PortNetworkPolicyRuleConstSharedPtr> rules_; // Allowed if empty.
  bool can_short_circuit_{true};
  bool has_pass_rules_{false};
  bool initialized_{false};
};

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

// PolicySnapshot is keyed by port ranges, and contains a list of PortNetworkPolicyRules's
// applicable to this range. A list is needed as rules may come from multiple sources (e.g.,
// resulting from use of named ports and numbered ports in Cilium NetworkPolicy at the same time).
class PolicySnapshot : public absl::btree_map<PortRange, PortNetworkPolicyRules, PortRangeCompare> {
public:
  using absl::btree_map<PortRange, PortNetworkPolicyRules, PortRangeCompare>::btree_map;
};

namespace {

const PortNetworkPolicyRules* findPortRules(const PolicySnapshot& map, uint16_t port) {
  // Look up with an exact port first, then fall back to the wildcard port (0). If policy is found
  // with the exact port, then the returned policy also contains all the wildcard port rules, so we
  // do not need to perform a separate wildcard port policy lookup. If no policy is defined for the
  // given port, then the wildcard port policy, consisting just of the wildcard port rules, is used,
  // if one exists.
  //
  // On lookups we'll set both ends of the port range to the same port number, which will find the
  // one range that it overlaps with in the map, if one exists (ref. PortRangeCompare definition).
  if (const auto it = map.find({port, port}); it != map.cend()) {
    return &it->second;
  }
  if (const auto wildcard = map.find({0, 0}); wildcard != map.cend()) {
    return &wildcard->second;
  }
  return nullptr;
}

} // namespace

PortPolicy::PortPolicy(const PolicySnapshot& map, uint16_t port, SelectorVersion selector_version)
    : port_rules_(findPortRules(map, port)),
      has_http_rules_(port_rules_ && port_rules_->hasHttpRules()),
      selector_version_(selector_version) {}

bool PortPolicy::allowed(uint16_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry) const {
  // Network layer policy has already been enforced. If there are no http rules, then there is
  // nothing to do.
  if (!has_http_rules_) {
    return true;
  }
  if (!port_rules_) {
    return false;
  }
  return port_rules_->getVerdict(proxy_id, remote_id, headers, log_entry, selector_version_) ==
         RuleVerdict::Allow;
}

bool PortPolicy::allowed(uint16_t proxy_id, uint32_t remote_id, absl::string_view sni) const {
  if (!port_rules_) {
    return false;
  }
  return port_rules_->getVerdict(proxy_id, remote_id, sni, selector_version_) == RuleVerdict::Allow;
}

Ssl::ContextSharedPtr PortPolicy::getServerTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig*& config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr tls_ctx;

  config = nullptr;
  raw_socket_allowed = false;
  if (port_rules_) {
    auto verdict = port_rules_->getServerTlsContext(proxy_id, remote_id, sni, tls_ctx, config,
                                                    selector_version_);
    raw_socket_allowed = verdict == RuleVerdict::Allow && tls_ctx == nullptr && config == nullptr;
  }
  return tls_ctx;
}

Ssl::ContextSharedPtr PortPolicy::getClientTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig*& config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr tls_ctx;

  config = nullptr;
  raw_socket_allowed = false;
  if (port_rules_) {
    auto verdict = port_rules_->getClientTlsContext(proxy_id, remote_id, sni, tls_ctx, config,
                                                    selector_version_);
    raw_socket_allowed = verdict == RuleVerdict::Allow && tls_ctx == nullptr && config == nullptr;
  }
  return tls_ctx;
}

namespace {
// Ranges overlap when one is not completely below or above the other
bool inline rangesOverlap(const PortRange& a, const PortRange& b) {
  // !(a.second < b.first || a.first > b.second)
  return a.second >= b.first && a.first <= b.second;
}
} // namespace

class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicy(const NetworkPolicyMapImpl& parent,
                    const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules,
                    const ResourceMapOverlay* resource_map) {
    for (const auto& rule : rules) {
      // Only TCP supported for HTTP
      if (rule.protocol() == envoy::config::core::v3::SocketAddress::TCP) {
        // Port may be zero, which matches any port.
        uint16_t port = rule.port();
        // End port may be zero, which means no range
        uint16_t end_port = rule.end_port();
        if (end_port < port) {
          if (end_port) {
            throw EnvoyException(fmt::format(
                "PortNetworkPolicy: Invalid port range, end port is less than start port {}-{}",
                port, end_port));
          }
          end_port = port;
        }

        if (port == 0) {
          if (end_port > 0) {
            throw EnvoyException(fmt::format(
                "PortNetworkPolicy: Invalid port range including the wildcard zero port {}-{}",
                port, end_port));
          }
        }

        ENVOY_LOG(trace,
                  "Cilium L7 PortNetworkPolicy(): installing TCP policy for "
                  "port range {}-{}",
                  port, end_port);

        auto rule_range = std::make_pair(port, end_port);
        auto pair = rules_.emplace(rule_range, PortNetworkPolicyRules{});
        auto it = pair.first;
        if (!pair.second) {
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): new entry [{}-{}] overlaps with [{}-{}]",
                    port, end_port, it->first.first, it->first.second);
          // Explicitly manage overlapping ranges by breaking them up.
          //
          // rules_ has the breaked up, non-overlapping ranges in order.
          //
          // While iterating through all the existing overlapping ranges:
          // - add new ranges when there are any gaps in the existing ranges (for the new range)
          // - split existing ranges if they are only partially overlapping with the new range
          // Then, as a separate step:
          // - add new rules to all of the (disjoint, ordered) ranges covered by the new range

          // The new range can overlap with multiple entries in the map, current iterator can
          // point to any one of them. Find the first entry the new entry overlaps with.
          auto last_overlap = it;
          while (it != rules_.begin()) {
            last_overlap = it;
            it--;
            if (!rangesOverlap(it->first, rule_range)) {
              break;
            }
          }
          it = last_overlap; // Move back up to the frontmost overlapping entry

          // absl::btree_map manipulation operations invalidate iterators, so we keep the range
          // (the map key) of the first overlapping entry in 'start_range' to be able to locate
          // the first range that needs the new rules after all the overlaps have been resolved.
          // 'start_key' is updated as needed below.
          auto start_range = it->first;

          // split the current entry due to partial overlap in the beginning.
          // For example, if the current entry is 80-8080 and we are adding 4040-9999,
          // the current entry should be split to two ranges 80-4039 and 4040-8080,
          // both of which should retain their current rules, but new rules should only be
          // added to the 2nd half covered by the new range 4040-9999.
          if (port > start_range.first) {
            RELEASE_ASSERT(port <= start_range.second, "non-overlapping range");
            auto rules = it->second;
            PortRange range1 = start_range;
            range1.second = port - 1;
            PortRange range2 = start_range;
            range2.first = port;

            rules_.erase(it);
            auto pr1 = rules_.insert({range1, rules});
            RELEASE_ASSERT(pr1.second, "Range split failed 1 begin");
            auto pr2 = rules_.insert({range2, rules});
            RELEASE_ASSERT(pr2.second, "Range split failed 2 begin");
            it = pr2.first;          // update current iterator
            start_range = it->first; // update the start range
          }

          // scan the range of the new rule, filling the gaps with new (partial) ranges
          bool new_range_end_covered = false;
          for (; it != rules_.end() && port <= end_port && end_port >= it->first.first; it++) {
            auto range = it->first;
            // create a new entry below the current one?
            if (port < range.first) {
              auto new_range = std::make_pair(port, std::min(end_port, uint16_t(range.first - 1)));
              auto new_pair = rules_.emplace(new_range, PortNetworkPolicyRules{});
              RELEASE_ASSERT(new_pair.second,
                             "duplicate entry when explicitly adding a new range!");
              // update the start range if a new start entry was added, which can happen only at the
              // beginning of this loop when port is still at the beginning of the rule range being
              // added.
              if (port == rule_range.first) {
                start_range = new_range;
              }
              // absl::btree_map insertion invalidates iterators, have to update.
              it = ++new_pair.first; // one past the new entry
              if (end_port < range.first) {
                // done
                break;
              }
              // covered upto range.first-1, continue from range.first
              port = range.first;
            }
            RELEASE_ASSERT(port == range.first, "port should match the start of the current range");
            // split the current range into two due to partial overlap in the end.
            if (end_port < range.second) {
              auto rules = it->second;
              PortRange range1 = it->first;
              range1.second = end_port;
              PortRange range2 = it->first;
              range2.first = end_port + 1;

              rules_.erase(it);
              auto pr1 = rules_.insert({range1, rules});
              RELEASE_ASSERT(pr1.second, "Range split failed 1 end");
              auto pr2 = rules_.insert({range2, rules});
              RELEASE_ASSERT(pr2.second, "Range split failed 2 end");
              it = pr2.first;      // one past the end of range
              port = end_port + 1; // one past the end
              break;
            } else {
              // Current range iterator completely covers the range to insert at the end.
              if (range.second == end_port) {
                new_range_end_covered = true;
                break;
              }
              // current entry completely covered by the new range, skip to the next
              port = range.second + 1;
            }
          }
          // create a new entry covering the end(if not already covered).
          if (!new_range_end_covered && port <= end_port) {
            auto new_range = std::make_pair(port, end_port);
            auto new_pair = rules_.emplace(new_range, PortNetworkPolicyRules{});
            RELEASE_ASSERT(new_pair.second,
                           "duplicate entry at end when explicitly adding a new range!");
            it = ++new_pair.first;
          }
          // make 'it' point to the first overlapping entry for the rule updates to follow
          it = rules_.find(start_range);
          RELEASE_ASSERT(it != rules_.end(), "first overlapping entry not found");
        }
        // Add rules to all the overlapping entries
        bool singular = rule_range.first == rule_range.second;
        for (; it != rules_.end() && rangesOverlap(it->first, rule_range); it++) {
          auto range = it->first;
          auto& rules = it->second;
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): Adding rules for [{}-{}] to [{}-{}]",
                    rule_range.first, rule_range.second, range.first, range.second);
          if (singular) {
            // Exact port rules go to the front of the list.
            // This gives precedence to exact port rules for TLS context selection.
            // prepend() inserts each rule at begin() while iterating forward,
            // so the relative order of rules from this batch is reversed. This
            // is harmless: equal-precedence rules are evaluated as alternatives
            // (stable sort only affects presentation/debug ordering).
            rules.prepend(parent, rule.rules(), resource_map);
          } else {
            // Rules with a non-trivial range go to the back of the list
            rules.append(parent, rule.rules(), resource_map);
          }
        }
      } else {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
      }
    }

    // Apply wildcard port rules to all ranges
    const PortNetworkPolicyRules* wildcard_rules = nullptr;
    for (auto& [port_range, rules] : rules_) {
      if (port_range.first == 0) {
        wildcard_rules = &rules;
        continue;
      }
      if (!wildcard_rules) {
        break;
      }
      rules.appendRules(wildcard_rules->rules_);
    }

    bool have_passes = false;

    // sort rules on each non-overlapping port range into descending precedence
    // port ranges themselves remain in the sorted order.
    // This way we can efficiently find the list of rules applicable to any given port,
    // and then process those rules in the order of decreasing precedence.
    for (auto& pair : rules_) {
      pair.second.sort();
      if (pair.second.has_pass_rules_) {
        have_passes = true;
      }
    }

    if (have_passes) {
      for (auto& [port_range, rules] : rules_) {
        (void)port_range;
        rules.prepareRuntimePasses();
      }

      // Pass-only ranges do not yield a final verdict, but keeping them would make
      // higher-level L7 checks treat the range as "no L7 rules" and allow by default.
      for (auto it = rules_.begin(); it != rules_.end();) {
        if (it->second.hasOnlyPassRules()) {
          it = rules_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  const PortPolicy findPortPolicy(uint16_t port, const SelectorVersion selector_version) const {
    return PortPolicy(rules_, port, selector_version);
  }

  void toString(int indent, std::string& res) const {
    if (rules_.empty()) {
      res.append(indent, ' ').append("rules: []\n");
    } else {
      res.append(indent, ' ').append("rules:\n");
      for (const auto& entry : rules_) {
        res.append(indent + 2, ' ')
            .append(fmt::format("[{}-{}]:\n", entry.first.first, entry.first.second));
        entry.second.toString(indent + 4, res);
      }
    }
  }

  PolicySnapshot rules_;
  bool has_http_rules_ = false;
};

// Construction is single-threaded, but all other use is from multiple worker threads using const
// methods.
class PolicyImpl : public Policy {
public:
  friend class NetworkPolicyMapImpl;
  PolicyImpl(const NetworkPolicyMapImpl& parent, uint64_t hash, const cilium::NetworkPolicy& proto,
             const ResourceMapOverlay* resource_map)
      : endpoint_id_(proto.endpoint_id()), hash_(hash), policy_proto_(proto), endpoint_ips_(proto),
        parent_(parent), ingress_(parent, policy_proto_.ingress_per_port_policies(), resource_map),
        egress_(parent, policy_proto_.egress_per_port_policies(), resource_map) {}

  const PortPolicy findPortPolicy(bool ingress, uint16_t port,
                                  SelectorVersion selector_version) const override {
    return ingress ? ingress_.findPortPolicy(port, selector_version)
                   : egress_.findPortPolicy(port, selector_version);
  }

  bool usesCurrentSelectors(const ResourceMapOverlay& resources) const {
    for (const auto* direction : {&ingress_, &egress_}) {
      for (const auto& [range, rules] : direction->rules_) {
        for (const auto& rule : rules.rules_) {
          for (const auto& selector : rule->selectors_) {
            if (resources.getSelectorHandleOrThrow(selector->name()) != selector) {
              return false;
            }
          }
        }
      }
    }
    return true;
  }

  uint32_t getEndpointID() const override { return endpoint_id_; }

  const IpAddressPair& getEndpointIPs() const override { return endpoint_ips_; }

  std::string string() const override {
    std::string res;
    res.append("ingress:\n");
    ingress_.toString(2, res);
    res.append("egress:\n");
    egress_.toString(2, res);
    return res;
  }

  void tlsWrapperMissingPolicyInc() const override { parent_.tlsWrapperMissingPolicyInc(); }

public:
  uint32_t endpoint_id_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;
  const IpAddressPair endpoint_ips_;

private:
  const NetworkPolicyMapImpl& parent_;
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

template <class EndpointIps> std::string endpointIpsForLog(const EndpointIps& endpoint_ips) {
  std::string formatted = "[";
  bool first = true;
  for (const auto& endpoint_ip : endpoint_ips) {
    if (!first) {
      formatted += ", ";
    }
    formatted += endpoint_ip;
    first = false;
  }
  formatted += "]";
  return formatted;
}

std::string describePolicyResourceForLog(const std::string& resource_name,
                                         const std::shared_ptr<const PolicyImpl>& policy) {
  ASSERT(policy != nullptr, "policy resource description requires a policy");
  return fmt::format("policy resource '{}' (endpoint_id {}, endpoint_ips {})", resource_name,
                     policy->endpoint_id_, endpointIpsForLog(policy->policy_proto_.endpoint_ips()));
}

std::string describePolicyResourceForLog(const std::string& resource_name,
                                         const cilium::NetworkPolicy& policy) {
  return fmt::format("policy resource '{}' (endpoint_id {}, endpoint_ips {})", resource_name,
                     policy.endpoint_id(), endpointIpsForLog(policy.endpoint_ips()));
}

// pass nullptr pending_resource_map for non-selector based policy!
std::shared_ptr<const PolicyImpl>
NetworkPolicyMapImpl::createOrReusePolicy(const std::string& resource_name,
                                          const cilium::NetworkPolicy& config,
                                          const ResourceMap& resource_map, bool is_new_stream,
                                          const ResourceMapOverlay* pending_resource_map) const {
  const uint64_t new_hash = MessageUtil::hash(config);
  if (!is_new_stream) {
    const auto* old_entry = resource_map.findEntry(resource_name);
    if (old_entry) {
      const auto* old_policy_entry = old_entry->policyResourceEntry();
      if (old_policy_entry) {
        const auto& old_policy = old_policy_entry->policy;
        if (old_policy && old_policy->hash_ == new_hash &&
            Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config) &&
            (pending_resource_map == nullptr ||
             old_policy->usesCurrentSelectors(*pending_resource_map))) {
          return old_policy;
        }
      }
    }
  }
  return std::make_shared<const PolicyImpl>(*this, new_hash, config, pending_resource_map);
}

std::pair<const std::string&, std::shared_ptr<const PolicyImpl>>
ResourceMapOverlay::findPolicyByEndpointIp(const std::string& endpoint_ip) const {
  const auto* key = findEntry(endpoint_ip);
  if (key) {
    const auto* ip_entry = key->policyEndpointIpEntry();
    if (ip_entry) {
      key = findEntry(ip_entry->policy_name);
      if (key) {
        const auto* policy_entry = key->policyResourceEntry();
        if (policy_entry) {
          return {ip_entry->policy_name, policy_entry->policy};
        }
      }
    }
  }
  static std::string empty_string;
  return {empty_string, nullptr};
}

std::string ResourceMapOverlay::describeExistingResourceKey(const std::string& key) const {
  const auto* entry = findEntry(key);
  if (entry == nullptr) {
    return fmt::format("resource key '{}'", key);
  }
  if (entry->selectorResourceEntry() != nullptr) {
    return fmt::format("selector resource '{}'", key);
  }
  if (const auto* policy_entry = entry->policyResourceEntry();
      policy_entry != nullptr && policy_entry->policy != nullptr) {
    return describePolicyResourceForLog(key, policy_entry->policy);
  }
  if (!entry->isPolicyEndpointIpEntry()) {
    return fmt::format("resource key '{}'", key);
  }

  auto [resource_name, policy] = findPolicyByEndpointIp(key);
  if (policy == nullptr) {
    return fmt::format("endpoint IP alias '{}'", key);
  }

  if (!resource_name.empty()) {
    return fmt::format("endpoint IP alias '{}' owned by {}", key,
                       describePolicyResourceForLog(resource_name, policy));
  }

  return fmt::format("endpoint IP alias '{}' owned by endpoint_id {} with endpoint_ips {}", key,
                     policy->endpoint_id_, endpointIpsForLog(policy->policy_proto_.endpoint_ips()));
}

PolicyLookupMap ResourceMapOverlay::toPolicyLookupMap() const {
  PolicyLookupMap policy_map;
  forEachEntry([&](const std::string& resource_name, const ResourceKey& resource_key) {
    const auto* policy_entry = resource_key.policyResourceEntry();
    if (policy_entry == nullptr || policy_entry->policy == nullptr) {
      return;
    }
    for (const auto& endpoint_ip : policy_entry->policy->policy_proto_.endpoint_ips()) {
      const bool inserted = policy_map.emplace(endpoint_ip, policy_entry->policy).second;
      RELEASE_ASSERT(
          inserted,
          fmt::format("duplicate endpoint IP alias '{}' while creating policy map snapshot from {}",
                      endpoint_ip,
                      describePolicyResourceForLog(resource_name, policy_entry->policy)));
    }
  });
  return policy_map;
}

void ResourceMapOverlay::erasePolicyResource(const std::string& resource_name,
                                             const std::shared_ptr<const PolicyImpl>& policy) {
  ASSERT(policy != nullptr, "policy resource key must carry a policy");
  for (const auto& endpoint_ip : policy->policy_proto_.endpoint_ips()) {
    erase(endpoint_ip);
  }
  erase(resource_name);
}

NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context,
                                   const envoy::config::core::v3::ConfigSource& config_source,
                                   bool subscribe, bool policy_secret_cache_enabled)
    : context_(context.serverFactoryContext()) {
  impl_ = std::make_shared<NetworkPolicyMapImpl>(context, config_source, subscribe,
                                                 policy_secret_cache_enabled);
}

NetworkPolicyMap::~NetworkPolicyMap() {
  // Policy map destruction happens when the last listener with the Cilium bpf_metadata listener
  // filter has drained out and is finally removed, and last connection of the old listener is
  // closed. This does not happen if new listener(s) with references to policy map are created in
  // the meanwhile.
  //
  // Destruction of the NetworkPolicyMapImpl must be made from the main thread to ensure integrity
  // of SDS subscription management. Since this can be called from a worker thread of the last
  // connection we must post the destruction to the main thread dispatcher in that case.
  if (Thread::MainThread::isMainOrTestThread()) {
    ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap: deleting NetworkPolicyMapImpl in main thread");
    impl_.reset();
    return;
  }

  ENVOY_LOG(debug,
            "Cilium L7 NetworkPolicyMap: posting NetworkPolicyMapImpl deletion to main thread");

  context_.mainThreadDispatcher().post([impl = std::move(impl_)]() mutable {
    ENVOY_LOG(
        debug,
        "Cilium L7 NetworkPolicyMap: Deferred deletion of NetworkPolicyMapImpl in main thread");
    impl.reset();
  });
}

bool NetworkPolicyMap::exists(const std::string& endpoint_policy_name) const {
  return impl_->load()->policies->contains(endpoint_policy_name);
}

void NetworkPolicyMap::configure(const envoy::config::core::v3::ConfigSource& config_source) {
  impl_->configure(config_source);
}

void NetworkPolicyMap::maybeAddInitTarget(Init::Manager& init_manager) {
  if (!impl_->started()) {
    init_manager.add(impl_->init_target_);
  }
}

ManagedGrpcSubscription& NetworkPolicyMap::managedSubscription() { return *impl_; }

const ManagedGrpcSubscription& NetworkPolicyMap::managedSubscription() const { return *impl_; }

PolicyStats& NetworkPolicyMap::stats() const { return impl_->stats_; }

std::shared_ptr<const Policy>
NetworkPolicyMap::getPolicyShared(const std::string& endpoint_policy_name) const {
  return impl_->getPolicyShared(endpoint_policy_name);
}

NetworkPolicyMapImpl::NetworkPolicyMapImpl(
    Server::Configuration::FactoryContext& context,
    const envoy::config::core::v3::ConfigSource& config_source, bool subscribe,
    bool policy_secret_cache_enabled)
    : ManagedGrpcSubscription(
          NetworkPolicyResourceTypeUrl, config_source,
          [](absl::string_view type_url) -> Config::OpaqueResourceDecoderSharedPtr {
            if (type_url == NetworkPolicyResourceTypeUrl) {
              return std::make_shared<NetworkPolicyResourceDecoder>();
            }
            return std::make_shared<NetworkPolicyDecoder>();
          },
          context.serverFactoryContext(),
          context.serverFactoryContext().serverScope().createScope("cilium.npds."), subscribe),
      context_(context.serverFactoryContext()), map_ptr_(nullptr),
      policy_stats_scope_(context_.serverScope().createScope("cilium.policy.")),
      init_target_(fmt::format("Cilium NetworkPolicy subscription start"),
                   [this]() {
                     // Production subscription is allowed to start from now on.
                     start();
                     // Allow listener init to continue before network policy updates are received
                     init_target_.ready();
                   }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context_, scope(), context_.messageValidationContext().dynamicValidationVisitor())),
      policy_secret_cache_(transport_factory_context_, std::cref(getConfigSource()),
                           policy_secret_cache_enabled),
      parked_init_manager_(std::make_unique<Init::ManagerImpl>("Cilium NetworkPolicyMap parked")),
      stats_{ALL_CILIUM_POLICY_COUNTERS(POOL_COUNTER(*policy_stats_scope_))
                 ALL_CILIUM_POLICY_GAUGES(POOL_GAUGE(*policy_stats_scope_))} {
  // Use listener init manager for subscription initialization
  context.initManager().add(init_target_);
  transport_factory_context_->setInitManager(*parked_init_manager_);

  // Allocate an initial policy map so that the map pointer is never a nullptr
  store(new PolicyMapSnapshot{std::make_shared<const PolicyLookupMap>(), versionMin, 0});
  ENVOY_LOG(trace, "NetworkPolicyMapImpl({}) created.", instance_id_);

  if (context_.admin().has_value()) {
    ENVOY_LOG(debug, "Registering NetworkPolicies to config tracker");
    config_tracker_entry_ = context_.admin()->getConfigTracker().add(
        "networkpolicies", [this](const Matchers::StringMatcher& name_matcher) {
          return dumpNetworkPolicyConfigs(name_matcher);
        });
    RELEASE_ASSERT(config_tracker_entry_, "");
  }
}

// NetworkPolicyMapImpl destructor must only be called from the main thread.
NetworkPolicyMapImpl::~NetworkPolicyMapImpl() {
  ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMapImpl({}): NetworkPolicyMap is deleted NOW!",
            instance_id_);
  delete load();
}

void NetworkPolicyMapImpl::reopenIpcache() {
  // Get ipcache singleton only if it was successfully created previously.
  // Cilium agent re-creates IP cache on restart, and the first accepted update on
  // the new stream must reopen it before workers enforce refreshed identities.
  IpCacheSharedPtr ipcache = IpCache::getIpCache(context_);
  if (ipcache) {
    ENVOY_LOG(info, "Reopening ipcache on new stream");
    ipcache->open();
  }
}

template <typename Logger>
void insertPolicyResource(ResourceMapOverlay& pending_resource_map,
                          const cilium::NetworkPolicy& config, const std::string& version_info,
                          bool is_new_stream, const std::string& resource_name,
                          const std::shared_ptr<const PolicyImpl>& policy, Logger logger) {
  if (!pending_resource_map.emplace(resource_name, ResourceKey::policyResource(policy))) {
    throw EnvoyException(fmt::format(
        "NetworkPolicyResource update for version {} has duplicate resource key '{}' on {} "
        "stream: incoming {} collides with existing {}",
        version_info, resource_name, is_new_stream ? "a new" : "an old",
        describePolicyResourceForLog(resource_name, config),
        pending_resource_map.describeExistingResourceKey(resource_name)));
  }
  for (const auto& endpoint_ip : config.endpoint_ips()) {
    logger(endpoint_ip);
    if (!pending_resource_map.emplace(endpoint_ip, ResourceKey::policyEndpointIp(resource_name))) {
      throw EnvoyException(fmt::format(
          "NetworkPolicyResource update for version {} has duplicate resource key '{}' on {} "
          "stream: incoming {} collides with existing {}",
          version_info, endpoint_ip, is_new_stream ? "a new" : "an old",
          describePolicyResourceForLog(resource_name, config),
          pending_resource_map.describeExistingResourceKey(endpoint_ip)));
    }
  }
}

void NetworkPolicyMapImpl::publishPolicyUpdate(ResourceMapOverlay&& pending_resource_map,
                                               uint64_t stream_generation,
                                               bool rebuild_policy_map) {
  const auto* previous = load();
  auto policies =
      rebuild_policy_map
          ? std::make_shared<const PolicyLookupMap>(pending_resource_map.toPolicyLookupMap())
          : previous->policies;
  const auto new_version = selector_map_.publishNextVersion();
  std::move(pending_resource_map).applyTo(resource_map_);
  if (new_version == 0 && !rebuild_policy_map && stream_generation == previous->stream_generation) {
    return;
  }
  auto snapshot = std::make_unique<PolicyMapSnapshot>(
      PolicyMapSnapshot{std::move(policies), new_version ? new_version : previous->selector_version,
                        stream_generation});

  // One release publishes every accepted change, including the selector version used by readers.
  const auto* old_snapshot = exchange(snapshot.release());
  stats_.policy_stream_generation_.set(stream_generation);
  scheduleSelectorGCAndDeferredDeletion(new_version, old_snapshot, rebuild_policy_map);
}

// removeInitManager must be called at the end of each policy update
void NetworkPolicyMapImpl::removeInitManager() {
  RELEASE_ASSERT(parked_init_manager_ != nullptr, "parked init manager must exist");

  const bool parked_wrong_state =
      parked_init_manager_->state() != Init::Manager::State::Uninitialized;
  if (parked_wrong_state) {
    ENVOY_LOG(warn,
              "Cilium NetworkPolicyMap parked init manager unexpectedly reached state {}; "
              "replacing it before re-installing",
              static_cast<int>(parked_init_manager_->state()));
  }

  envoy::admin::v3::UnreadyTargetsDumps parked_dumps;
  parked_init_manager_->dumpUnreadyTargets(parked_dumps);
  bool parked_has_targets = false;
  for (const auto& parked_dump : parked_dumps.unready_targets_dumps()) {
    if (!parked_dump.target_names().empty()) {
      parked_has_targets = true;
      ENVOY_LOG(
          warn,
          "Cilium NetworkPolicyMap parked init manager unexpectedly accumulated targets [{}]{}; "
          "replacing it before re-installing",
          absl::StrJoin(parked_dump.target_names(), ", "),
          parked_wrong_state
              ? fmt::format(" in state {}", static_cast<int>(parked_init_manager_->state()))
              : "");
    }
  }

  // replace parked init manager if it got to a bad state
  if (parked_wrong_state || parked_has_targets) {
    parked_init_manager_ = std::make_unique<Init::ManagerImpl>("Cilium NetworkPolicyMap parked");
  }

  // Restore the parked init manager after a policy-version-specific init manager has been
  // installed for the duration of the update.
  transport_factory_context_->setInitManager(*parked_init_manager_);
}

void NetworkPolicyMapImpl::scheduleSelectorDeferredDeletion(
    DeferredDeletion<SelectorInstance>&& deferred) {
  if (deferred.empty()) {
    return;
  }
  auto deferred_owner = std::make_shared<DeferredDeletion<SelectorInstance>>(std::move(deferred));
  // The callback exists only to keep the deferred-deletion batch alive until all workers have
  // quiesced once more. The batch deletes its nodes from the closure destructor.
  runAfterAllThreads([deferred_owner]() {});
}

void NetworkPolicyMapImpl::scheduleSelectorGCAndDeferredDeletion(
    uint64_t published_version, const PolicyMapSnapshot* old_policy_map, bool policies_changed) {
  runAfterAllThreads(
      [shared_this = sharedFromThis(), published_version, old_policy_map, policies_changed]() {
        // Old policy views and selector versions are no longer borrowed after this grace period.
        delete old_policy_map;
        if (published_version != 0) {
          shared_this->scheduleSelectorDeferredDeletion(
              shared_this->selector_map_.gc(published_version));
        }
        if (policies_changed) {
          shared_this->policy_secret_cache_.prune();
        }
      });
}

absl::Status
NetworkPolicyMapImpl::onConfigUpdate(const std::vector<Config::DecodedResourceRef>& resources,
                                     const std::string& version_info) {
  if (fallbackOnEmptyResponse(resources.empty())) {
    return absl::OkStatus();
  }
  return getTypeUrl() == NetworkPolicyResourceTypeUrl
             ? onNprdsConfigUpdate(resources, {}, version_info, true)
             : onNpdsConfigUpdate(resources, {}, version_info, true);
}

absl::Status NetworkPolicyMapImpl::onConfigUpdate(
    const std::vector<Config::DecodedResourceRef>& resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources,
    const std::string& version_info) {
  if (fallbackOnEmptyResponse(resources.empty() && removed_resources.empty())) {
    return absl::OkStatus();
  }
  return getTypeUrl() == NetworkPolicyResourceTypeUrl
             ? onNprdsConfigUpdate(resources, removed_resources, version_info, false)
             : onNpdsConfigUpdate(resources, removed_resources, version_info, false);
}

void NetworkPolicyMapImpl::validatePolicy(const std::string& resource_name,
                                          const cilium::NetworkPolicy& config,
                                          const std::string& version_info) {
  if (config.endpoint_ips().empty()) {
    throw EnvoyException("NetworkPolicyResource has no endpoint ips");
  }
  for (const auto* direction :
       {&config.ingress_per_port_policies(), &config.egress_per_port_policies()}) {
    for (const auto& port_policy : *direction) {
      if (!port_policy.port_name().empty()) {
        throw EnvoyException("Named-port policies are not supported");
      }
    }
  }
  if (config.endpoint_id() == 0) {
    throw EnvoyException("NetworkPolicyResource endpoint_id must be non-zero");
  }
  ENVOY_LOG(debug, "Received NetworkPolicy {} for endpoint {} in version {}", resource_name,
            config.endpoint_id(), version_info);
}

absl::Status NetworkPolicyMapImpl::onNpdsConfigUpdate(
    const std::vector<Config::DecodedResourceRef>& resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources,
    const std::string& version_info, bool sotw) {
  stats_.updates_total_.inc();
  const auto generation = streamGeneration();
  const bool is_new_stream = generation != load()->stream_generation;
  const auto& base = is_new_stream ? empty_resource_map_ : resource_map_;
  ResourceMapOverlay pending = sotw ? ResourceMapOverlay() : ResourceMapOverlay(base);
  Init::ManagerImpl init_manager(fmt::format("NetworkPolicy version {}", version_info));
  transport_factory_context_->setInitManager(init_manager);
  try {
    if (is_new_stream) {
      policy_secret_cache_.reset();
      reopenIpcache();
    }
    for (const auto& name : removed_resources) {
      validateResourceName(name, "NetworkPolicy removed resource name");
      const auto* entry = pending.findEntry(name);
      if (!entry) {
        continue;
      }
      if (!entry->policyResourceEntry()) {
        throw EnvoyException(fmt::format("NetworkPolicy removed resource '{}' is a policy endpoint "
                                         "IP alias, not a resource name",
                                         name));
      }
      pending.erasePolicyResource(name, entry->policyResourceEntry()->policy);
    }
    for (const auto& resource : resources) {
      const auto& config = dynamic_cast<const cilium::NetworkPolicy&>(resource.get().resource());
      const auto& name = resource.get().name();
      validateResourceName(name, "NetworkPolicy resource name");
      validatePolicy(name, config, version_info);
      if (!sotw) {
        pending.erasePolicyResourceIfPresent(name);
      }
    }
    for (const auto& resource : resources) {
      const auto& config = dynamic_cast<const cilium::NetworkPolicy&>(resource.get().resource());
      const auto& name = resource.get().name();
      auto policy = createOrReusePolicy(name, config, base, is_new_stream, nullptr);
      insertPolicyResource(pending, config, version_info, is_new_stream, name, policy,
                           [](absl::string_view) {});
    }
    init_manager.initialize(Init::WatcherImpl("NetworkPolicy", []() {}));
  } catch (...) {
    removeInitManager();
    stats_.updates_rejected_.inc();
    try {
      throw;
    } catch (const std::bad_cast&) {
      throw EnvoyException("Invalid resource type for Cilium NetworkPolicy");
    }
  }
  removeInitManager();

  // Legacy NPDS remains all-or-nothing. Do not touch selector state until the update succeeds.
  if (is_new_stream) {
    selector_map_.prepareNextVersion();
    selector_map_.clear();
  }
  if (sotw || is_new_stream) {
    resource_map_.clear();
  }
  publishPolicyUpdate(std::move(pending), generation, true);
  stats_.update_success_.inc();
  return absl::OkStatus();
}

// Each candidate owns its tentative state until validation, initialization, and key ownership have
// been resolved. In contrast to legacy NPDS, failed resources do not discard successful siblings.
class NprdsUpdate {
public:
  NprdsUpdate(NetworkPolicyMapImpl& parent, uint64_t generation, bool new_stream,
              const std::string& version_info)
      : parent_(parent), generation_(generation), new_stream_(new_stream),
        version_info_(version_info),
        base_(new_stream ? parent.empty_resource_map_ : parent.resource_map_), resources_(base_) {}

  void process(const std::vector<Config::DecodedResourceRef>& resources,
               const Protobuf::RepeatedPtrField<std::string>& removed_resources, bool sotw) {
    parse(resources);
    if (sotw) {
      for (const auto& [name, entry] : base_) {
        if (!entry.isPolicyEndpointIpEntry() && !received_names_.contains(name)) {
          remove(name);
        }
      }
    } else {
      for (const auto& name : removed_resources) {
        try {
          validateResourceName(name, "NetworkPolicyResource removed resource name");
          remove(name);
          accepted_removal_ = true;
        } catch (const EnvoyException& e) {
          errors_.push_back(fmt::format("{}: {}", name, e.what()));
        }
      }
    }

    ResourceMapOverlay selector_resources = resources_;
    for (auto& candidate : candidates_) {
      if (!candidate.accepted || !candidate.selector) {
        continue;
      }
      selector_resources.put(candidate.name, ResourceKey::selectorResource(candidate.selector));
    }
    for (auto& candidate : candidates_) {
      if (!candidate.accepted || candidate.selector) {
        continue;
      }
      try {
        initializePolicy(candidate, selector_resources);
      } catch (const EnvoyException& e) {
        reject(candidate, e.what(), false);
      }
    }

    // Only initialized replacements release their old aliases. Restoration below propagates a
    // failure to any candidate relying on aliases that the failed replacement must retain.
    for (const auto& candidate : candidates_) {
      if (candidate.accepted && candidate.policy) {
        resources_.erasePolicyResourceIfPresent(candidate.name);
      }
    }
    for (auto& candidate : candidates_) {
      if (candidate.accepted && candidate.selector) {
        install(candidate);
      }
    }
    for (auto& candidate : candidates_) {
      if (candidate.accepted && candidate.policy) {
        install(candidate);
      }
    }
    bool changed;
    do {
      changed = false;
      for (auto& candidate : candidates_) {
        if (!candidate.accepted || !candidate.policy) {
          continue;
        }
        try {
          if (!candidate.policy->usesCurrentSelectors(resources_)) {
            throw EnvoyException("policy references a rejected selector resource");
          }
        } catch (const EnvoyException& e) {
          reject(candidate, e.what(), true);
          changed = true;
        }
      }
    } while (changed);
  }

  bool hasAcceptedResources() const {
    return accepted_removal_ || std::ranges::any_of(candidates_, [](const auto& candidate) {
             return candidate.accepted;
           });
  }

  void publish() {
    auto& selectors = parent_.selector_map_;
    selectors.prepareNextVersion();
    bool policies_changed = new_stream_;
    if (new_stream_) {
      selectors.clear();
      parent_.resource_map_.clear();
    }
    for (const auto& name : removals_) {
      const auto* old = base_.findEntry(name);
      if (old && old->selectorResourceEntry()) {
        const auto replacement = candidates_by_name_.find(name);
        if (replacement == candidates_by_name_.end() ||
            !candidates_[replacement->second].accepted ||
            !candidates_[replacement->second].selector) {
          selectors.clear(name);
        }
      } else if (old && old->policyResourceEntry()) {
        policies_changed = true;
      }
    }
    for (auto& candidate : candidates_) {
      if (!candidate.accepted) {
        continue;
      }
      if (candidate.selector_value) {
        selectors.insert(candidate.name, candidate.selector_value.release(), candidate.selector);
      } else if (candidate.policy) {
        const auto* old = base_.findEntry(candidate.name);
        policies_changed |= !old || !old->policyResourceEntry() ||
                            old->policyResourceEntry()->policy != candidate.policy;
      }
    }
    parent_.publishPolicyUpdate(std::move(resources_), generation_, policies_changed);
  }

  absl::Status status() const {
    if (errors_.empty()) {
      return absl::OkStatus();
    }
    // Match LDS/CDS error_detail: a resource-kind prefix followed by "name: error" entries.
    return absl::InvalidArgumentError(fmt::format(
        "Error adding/updating network policy resource(s) {}", absl::StrJoin(errors_, "\n")));
  }

private:
  struct Candidate {
    std::string name;
    const cilium::NetworkPolicyResource* config{nullptr};
    std::shared_ptr<NamedSelectorValue> selector;
    std::unique_ptr<SelectorInstance> selector_value;
    std::shared_ptr<const PolicyImpl> policy;
    bool accepted{true};
    bool installed{false};
  };

  void parse(const std::vector<Config::DecodedResourceRef>& resources) {
    candidates_.reserve(resources.size());
    for (const auto& resource : resources) {
      const auto& name = resource.get().name();
      if (!received_names_.insert(name).second) {
        errors_.push_back(fmt::format("{}: duplicate resource name", name));
        continue;
      }
      auto& candidate = candidates_.emplace_back();
      candidate.name = name;
      candidates_by_name_.emplace(name, candidates_.size() - 1);
      try {
        validateResourceName(name, "NetworkPolicyResource resource name");
        const auto& payload = resource.get().resource();
        if (const auto* error = dynamic_cast<const Protobuf::StringValue*>(&payload)) {
          throw EnvoyException(error->value());
        }
        candidate.config = dynamic_cast<const cilium::NetworkPolicyResource*>(&payload);
        if (!candidate.config) {
          throw EnvoyException("Invalid resource type for Cilium NetworkPolicyResource");
        }
        MessageUtil::validate(*candidate.config, ProtobufMessage::getNullValidationVisitor());
        switch (candidate.config->resource_case()) {
        case cilium::NetworkPolicyResource::kSelector:
          prepareSelector(candidate);
          break;
        case cilium::NetworkPolicyResource::kPolicy:
          parent_.validatePolicy(name, candidate.config->policy(), version_info_);
          break;
        case cilium::NetworkPolicyResource::kEndpoint:
        case cilium::NetworkPolicyResource::kPeer:
          throw EnvoyException("NetworkPolicyResource payload is not supported");
        case cilium::NetworkPolicyResource::RESOURCE_NOT_SET:
          throw EnvoyException("NetworkPolicyResource has no payload");
        }
      } catch (const EnvoyException& e) {
        reject(candidate, e.what(), false);
      }
    }
  }

  void prepareSelector(Candidate& candidate) {
    const auto& config = candidate.config->selector();
    const auto* old = base_.findEntry(candidate.name);
    if (old && old->selectorResourceEntry()) {
      candidate.selector = std::const_pointer_cast<NamedSelectorValue>(
          std::static_pointer_cast<const NamedSelectorValue>(old->selectorResourceEntry()->handle));
      const auto* value = candidate.selector->get(parent_.load()->selector_version);
      if (value && value->size() == static_cast<size_t>(config.identities_size()) &&
          std::ranges::all_of(config.identities(),
                              [value](uint32_t identity) { return value->contains(identity); })) {
        return;
      }
    } else {
      candidate.selector = std::make_shared<NamedSelectorValue>(candidate.name);
    }
    candidate.selector_value = std::make_unique<SelectorInstance>();
    candidate.selector_value->insert(config.identities().begin(), config.identities().end());
  }

  void initializePolicy(Candidate& candidate, const ResourceMapOverlay& selectors) {
    Init::ManagerImpl init_manager(
        fmt::format("NetworkPolicyResource {} version {}", candidate.name, version_info_));
    parent_.transport_factory_context_->setInitManager(init_manager);
    try {
      candidate.policy = parent_.createOrReusePolicy(candidate.name, candidate.config->policy(),
                                                     base_, new_stream_, &selectors);
      init_manager.initialize(Init::WatcherImpl(candidate.name, []() {}));
    } catch (...) {
      candidate.policy.reset();
      parent_.removeInitManager();
      throw;
    }
    parent_.removeInitManager();
  }

  void remove(const std::string& name) {
    const auto* entry = resources_.findEntry(name);
    if (entry && entry->isPolicyEndpointIpEntry()) {
      throw EnvoyException(fmt::format("NetworkPolicyResource removed resource '{}' is a policy "
                                       "endpoint IP alias, not a resource name",
                                       name));
    }
    removals_.insert(name);
    if (entry && entry->policyResourceEntry()) {
      resources_.erasePolicyResource(name, entry->policyResourceEntry()->policy);
    } else {
      resources_.erase(name);
    }
  }

  static std::string owner(const std::string& key, const ResourceKey& entry) {
    const auto* alias = entry.policyEndpointIpEntry();
    return alias ? alias->policy_name : key;
  }

  void install(Candidate& candidate) {
    std::vector<std::string> keys{candidate.name};
    if (candidate.policy) {
      for (const auto& ip : candidate.config->policy().endpoint_ips()) {
        keys.push_back(ip);
      }
    }
    absl::flat_hash_set<std::string> seen;
    for (const auto& key : keys) {
      const auto* existing = resources_.findEntry(key);
      if (!seen.insert(key).second || (existing && !(key == candidate.name && candidate.selector &&
                                                     existing->selectorResourceEntry()))) {
        reject(candidate,
               fmt::format(
                   "duplicate resource key '{}': incoming {} "
                   "collides with existing {}",
                   key,
                   candidate.selector
                       ? fmt::format("selector resource '{}'", candidate.name)
                       : describePolicyResourceForLog(candidate.name, candidate.config->policy()),
                   resources_.describeExistingResourceKey(key)),
               true);
        return;
      }
    }
    if (candidate.selector) {
      resources_.put(candidate.name, ResourceKey::selectorResource(candidate.selector));
    } else {
      resources_.put(candidate.name, ResourceKey::policyResource(candidate.policy));
      for (const auto& ip : candidate.config->policy().endpoint_ips()) {
        resources_.put(ip, ResourceKey::policyEndpointIp(candidate.name));
      }
    }
    candidate.installed = true;
  }

  void reject(Candidate& candidate, const std::string& error, bool restore) {
    if (!candidate.accepted) {
      return;
    }
    candidate.accepted = false;
    errors_.push_back(fmt::format("{}: {}", candidate.name, error));
    if (!restore) {
      return;
    }
    if (candidate.installed) {
      resources_.erase(candidate.name);
      if (candidate.policy) {
        for (const auto& ip : candidate.config->policy().endpoint_ips()) {
          resources_.erase(ip);
        }
      }
      candidate.installed = false;
    }
    const auto* old =
        removals_.contains(candidate.name) ? nullptr : base_.findEntry(candidate.name);
    if (!old || old->isPolicyEndpointIpEntry()) {
      return;
    }
    restoreKey(candidate.name, *old);
    if (const auto* policy = old->policyResourceEntry()) {
      for (const auto& ip : policy->policy->policy_proto_.endpoint_ips()) {
        restoreKey(ip, ResourceKey::policyEndpointIp(candidate.name));
      }
    }
  }

  void restoreKey(const std::string& key, const ResourceKey& value) {
    const auto* existing = resources_.findEntry(key);
    if (existing && owner(key, *existing) != owner(key, value)) {
      const auto it = candidates_by_name_.find(owner(key, *existing));
      RELEASE_ASSERT(it != candidates_by_name_.end(), "retained resource keys must be disjoint");
      auto& conflicting = candidates_[it->second];
      reject(conflicting,
             fmt::format("resource key '{}' is retained by failed resource '{}'", key,
                         owner(key, value)),
             true);
    }
    resources_.put(key, value);
  }

  NetworkPolicyMapImpl& parent_;
  const uint64_t generation_;
  const bool new_stream_;
  const std::string& version_info_;
  const ResourceMap& base_;
  ResourceMapOverlay resources_;
  std::vector<Candidate> candidates_;
  absl::flat_hash_map<std::string, size_t> candidates_by_name_;
  absl::flat_hash_set<std::string> received_names_;
  absl::flat_hash_set<std::string> removals_;
  std::vector<std::string> errors_;
  bool accepted_removal_{false};
};

absl::Status NetworkPolicyMapImpl::onNprdsConfigUpdate(
    const std::vector<Config::DecodedResourceRef>& resources,
    const Protobuf::RepeatedPtrField<std::string>& removed_resources,
    const std::string& version_info, bool sotw) {
  stats_.updates_total_.inc();
  const auto generation = streamGeneration();
  const bool is_new_stream = generation != load()->stream_generation;
  if (is_new_stream) {
    policy_secret_cache_.reset();
    reopenIpcache();
  }
  NprdsUpdate update(*this, generation, is_new_stream, version_info);
  update.process(resources, removed_resources, sotw);
  const auto status = update.status();
  // A nonempty NPRDS response commits a new namespace if any resource succeeds, even when
  // the response must be NACKed. The initial empty capability response is intercepted earlier.
  if (!is_new_stream || (resources.empty() && removed_resources.empty()) ||
      update.hasAcceptedResources()) {
    update.publish();
  }
  if (!status.ok()) {
    stats_.updates_rejected_.inc();
  } else {
    stats_.update_success_.inc();
  }
  return status;
}

ProtobufTypes::MessagePtr
NetworkPolicyMapImpl::dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher) {
  ENVOY_LOG(debug, "Writing NetworkPolicies to NetworkPoliciesConfigDump");

  std::vector<uint64_t> policy_endpoint_ids;
  auto config_dump = std::make_unique<cilium::NetworkPoliciesConfigDump>();
  for (const auto& item : *load()->policies) {
    // filter duplicates (policies are stored per endpoint ip)
    if (std::find(policy_endpoint_ids.begin(), policy_endpoint_ids.end(),
                  item.second->policy_proto_.endpoint_id()) != policy_endpoint_ids.end()) {
      continue;
    }

    if (!name_matcher.match(item.first)) {
      continue;
    }

    config_dump->mutable_networkpolicies()->Add()->CopyFrom(item.second->policy_proto_);
    policy_endpoint_ids.emplace_back(item.second->policy_proto_.endpoint_id());
  }

  return config_dump;
}

// Allow-all Egress policy
class AllowAllEgressPolicyImpl : public Policy {
public:
  AllowAllEgressPolicyImpl() {
    empty_map_.emplace(std::make_pair(uint16_t(1), uint16_t(1)), PortNetworkPolicyRules{});
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t, SelectorVersion) const override {
    return ingress ? PortPolicy(empty_map_, 0, versionMin) : PortPolicy(empty_map_, 1, versionMin);
  }

  bool allowed(bool ingress, uint16_t, uint32_t, uint16_t, Http::RequestHeaderMap&,
               AccessLog::Entry&, SelectorVersion) const override {
    return !ingress;
  }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "AllowAllEgressPolicyImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicySnapshot empty_map_;
  static const IpAddressPair empty_ips;
};
const IpAddressPair AllowAllEgressPolicyImpl::empty_ips{};

const PolicyInstance NetworkPolicyMap::getAllowAllEgressPolicy() {
  static AllowAllEgressPolicyImpl allow_all_egress_policy;
  return {allow_all_egress_policy, versionMin};
}

// Deny-all policy
class DenyAllPolicyImpl : public Policy {
public:
  DenyAllPolicyImpl() = default;

  const PortPolicy findPortPolicy(bool, uint16_t, SelectorVersion) const override {
    return PortPolicy(empty_map_, 0, versionMin);
  }

  bool allowed(bool, uint16_t, uint32_t, uint16_t, Http::RequestHeaderMap&, AccessLog::Entry&,
               SelectorVersion) const override {
    return false;
  }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "DenyAllPolicyImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicySnapshot empty_map_;
  static const IpAddressPair empty_ips;
};
const IpAddressPair DenyAllPolicyImpl::empty_ips{};

const PolicyInstance NetworkPolicyMap::getDenyAllPolicy() {
  static DenyAllPolicyImpl deny_all_policy;
  return {deny_all_policy, versionMin};
}

const PolicyInstance NetworkPolicyMapImpl::getPolicyInstance(const std::string& endpoint_ip,
                                                             bool allow_egress) const {
  const auto* snapshot = load();
  auto it = snapshot->policies->find(endpoint_ip);
  if (it != snapshot->policies->end()) {
    return {*it->second, snapshot->selector_version};
  }
  return allow_egress ? NetworkPolicyMap::getAllowAllEgressPolicy()
                      : NetworkPolicyMap::getDenyAllPolicy();
}

std::shared_ptr<const Policy>
NetworkPolicyMapImpl::getPolicyShared(const std::string& endpoint_ip) const {
  const auto& map = *load()->policies;
  auto it = map.find(endpoint_ip);
  if (it != map.end()) {
    return it->second;
  }
  return nullptr;
}

// Missing policies deny ingress and optionally allow egress for Cilium Ingress listeners.
const PolicyInstance NetworkPolicyMap::getPolicyInstance(const std::string& endpoint_ip,
                                                         bool default_allow_egress) const {
  return impl_->getPolicyInstance(endpoint_ip, default_allow_egress);
}

} // namespace Cilium
} // namespace Envoy
