#pragma once

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/common/pure.h"
#include "envoy/common/regex.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/network/address.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/stats/stats_macros.h" // IWYU pragma: keep

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/common/thread.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/npds.pb.validate.h" // IWYU pragma: keep
#include "re2/re2.h"

namespace Envoy {
namespace Cilium {

class PortNetworkPolicyRules;
class PolicySnapshot;

// PortPolicy holds a reference to a set of rules in a policy map that apply to the given port.
// Methods then iterate through the set to determine if policy allows or denies. This is needed to
// support multiple rules on the same port, like when named ports are used, or when deny policies
// may be present.
class PortPolicy : public Logger::Loggable<Logger::Id::config> {
protected:
  friend class PortNetworkPolicy;
  friend class DenyAllPolicyInstanceImpl;
  friend class AllowAllEgressPolicyInstanceImpl;
  PortPolicy(const PolicySnapshot& map, uint16_t port);

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
                                            const Ssl::ContextConfig*& config,
                                            bool& raw_socket_allowed) const;
  // getClientTlsContext returns the client TLS context, if any. If a non-null pointer is returned,
  // then also the config pointer '*config' is set.
  // If '*config' is nullptr and 'raw_socket_allowed' is 'true' on return then the policy
  // allows the connection without TLS and a raw socket should be used.
  Ssl::ContextSharedPtr getClientTlsContext(uint16_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig*& config,
                                            bool& raw_socket_allowed) const;

private:
  // using raw pointers by design:
  // - pointer to distinguish between no rules and empty rules
  // - not using shared pointer to not allow a worker thread to hold the last reference to policy
  //   rule(s), as they must be destructed from the main thread only.
  // - lifetime on policy updates is managed explicitly by posting a lambda to all worker threads
  //   before the old rules are deleted; worker thread drop references to policy rules before
  //   returning to the event loop, so after the posted lambda executes it is safe to delete the old
  //   rules.
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

  Network::Address::InstanceConstSharedPtr ipv4_;
  Network::Address::InstanceConstSharedPtr ipv6_;
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

  virtual uint32_t getEndpointID() const PURE;

  virtual const IpAddressPair& getEndpointIPs() const PURE;

  virtual std::string string() const PURE;

  virtual void tlsWrapperMissingPolicyInc() const PURE;
};
using PolicyInstanceConstSharedPtr = std::shared_ptr<const PolicyInstance>;

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
#define ALL_CILIUM_POLICY_STATS(COUNTER)	\
  COUNTER(updates_total)				\
  COUNTER(updates_rejected)				\
  COUNTER(tls_wrapper_missing_policy) \
  COUNTER(update_success)
// clang-format on

/**
 * Struct definition for all policy stats. @see stats_macros.h
 */
struct PolicyStats {
  ALL_CILIUM_POLICY_STATS(GENERATE_COUNTER_STRUCT)
};

class NetworkPolicyMapImpl;

class NetworkPolicyMap : public Singleton::Instance, public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(Server::Configuration::FactoryContext& context,
                   const envoy::config::core::v3::ConfigSource& npds_config,
                   bool subscribe = false);
  ~NetworkPolicyMap() override;

  bool exists(const std::string& endpoint_policy_name) const;

  const PolicyInstance& getPolicyInstance(const std::string& endpoint_policy_name,
                                          bool allow_egress) const;

  static PolicyInstance& getDenyAllPolicy();
  static PolicyInstance& getAllowAllEgressPolicy();

protected:
  friend class CiliumNetworkPolicyTest;
  friend struct TestHelper;
  PolicyStats& statsForTest() const;
  void startSubscriptionForTest(std::unique_ptr<Envoy::Config::Subscription>&& subscription);
  Envoy::Config::SubscriptionCallbacks& subscriptionCallbacksForTest() const;

private:
  Server::Configuration::ServerFactoryContext& context_;
  std::unique_ptr<NetworkPolicyMapImpl> impl_;
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
    return pattern.empty() || re2::RE2::FullMatch(pattern, getValidPatternRE());
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
