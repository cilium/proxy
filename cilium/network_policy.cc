#include "cilium/network_policy.h"

#include <string>

#include "envoy/type/matcher/v3/metadata.pb.h"

#include "source/common/common/matchers.h"
#include "source/common/config/utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h"

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "cilium/grpc_subscription.h"
#include "cilium/secret_watcher.h"

namespace Envoy {
namespace Cilium {

uint64_t NetworkPolicyMap::instance_id_ = 0;

// PortPolicy used in cases where no rules are found -> always allow
class AllowPortNetworkPolicyRule : public PortPolicy {
public:
  AllowPortNetworkPolicyRule(){};

  bool Matches(absl::string_view, uint64_t) const override { return true; }

  // PortPolicy
  bool useProxylib(std::string&) const override { return false; }

  // Envoy Metadata matcher
  bool allowed(const envoy::config::core::v3::Metadata&) const override {
    return true; // allowed by default
  }

  const Ssl::ContextConfig& getServerTlsContextConfig() const override {
    return *empty_context_config; // not used
  }
  Ssl::ContextSharedPtr getServerTlsContext() const override { return nullptr; }
  const Ssl::ContextConfig& getClientTlsContextConfig() const override {
    return *empty_context_config; // not used
  }
  Ssl::ContextSharedPtr getClientTlsContext() const override { return nullptr; }

private:
  static Extensions::TransportSockets::Tls::ClientContextConfigImpl* empty_context_config;
};
Extensions::TransportSockets::Tls::ClientContextConfigImpl*
    AllowPortNetworkPolicyRule::empty_context_config{nullptr};

PortPolicyConstSharedPtr allowPortNetworkPolicyRule =
    std::make_shared<AllowPortNetworkPolicyRule>();

namespace {
// PortRangeCompare returns true if both ends of range 'a' are less than the
// corresponding ends of range 'b'. std::less compares 'pair.second' only if the
// first elements are equal, which does not work for range lookups, where we
// look with a pair where both elements have the same value of interest.
//
// NOTE: This relies on the invariant that in any given range R, R.first <= R.second.
// We do not test for this here, but this must be enforced when creating the ranges!
struct PortRangeCompare {
  bool operator()(const std::pair<uint16_t, uint16_t>& a,
                  const std::pair<uint16_t, uint16_t>& b) const {
    // For a range pair first <= second; less if a is completely below b
    return a.second < b.first;
  }
};
} // namespace

// Allow-all Egress policy
class AllowAllEgressPolicyInstanceImpl : public PolicyInstance {
public:
  AllowAllEgressPolicyInstanceImpl() {}

  bool Allowed(bool ingress, uint16_t, uint64_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return ingress ? false : true;
  }

  const PortPolicyConstSharedPtr findPortPolicy(bool ingress, uint16_t, uint64_t) const override {
    return ingress ? nullptr : allowPortNetworkPolicyRule;
  }

  bool useProxylib(bool, uint16_t, uint64_t, std::string&) const override { return false; }

  const std::string& conntrackName() const override { return empty_string; }

  uint32_t getEndpointID() const override { return 0; }

  const IPAddressPair& getEndpointIPs() const override { return empty_ips; }

private:
  static const std::string empty_string;
  static const IPAddressPair empty_ips;
};
const std::string AllowAllEgressPolicyInstanceImpl::empty_string = "";
const IPAddressPair AllowAllEgressPolicyInstanceImpl::empty_ips{};

IPAddressPair::IPAddressPair(const cilium::NetworkPolicy& proto) {
  for (const auto& ipAddr : proto.endpoint_ips()) {
    auto ip = Network::Utility::parseInternetAddressNoThrow(ipAddr);
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

// Construction is single-threaded, but all other use is from multiple worker threads using const
// methods.
class PolicyInstanceImpl : public PolicyInstance {
public:
  PolicyInstanceImpl(const NetworkPolicyMap& parent, uint64_t hash,
                     const cilium::NetworkPolicy& proto)
      : conntrack_map_name_(proto.conntrack_map_name()), endpoint_id_(proto.endpoint_id()),
        hash_(hash), policy_proto_(proto), endpoint_ips_(proto),
        ingress_(parent, policy_proto_.ingress_per_port_policies()),
        egress_(parent, policy_proto_.egress_per_port_policies()) {}

protected:
  class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    class HeaderMatch {
    public:
      HeaderMatch(const NetworkPolicyMap& parent, const cilium::HeaderMatch& config)
          : name_(config.name()), value_(config.value()), match_action_(config.match_action()),
            mismatch_action_(config.mismatch_action()) {
        if (config.value_sds_secret().length() > 0)
          secret_ = std::make_unique<SecretWatcher>(parent, config.value_sds_secret());
      }

      void logRejected(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
        log_entry.AddRejected(name_.get(), !secret_ ? value : "[redacted]");
      }

      void logMissing(Cilium::AccessLog::Entry& log_entry, absl::string_view value) const {
        log_entry.AddMissing(name_.get(), !secret_ ? value : "[redacted]");
      }

      // Returns 'true' if matching can continue
      bool Matches(Envoy::Http::RequestHeaderMap& headers,
                   Cilium::AccessLog::Entry& log_entry) const {
        bool matches = false;
        const std::string* match_value = &value_;
        const auto header_value = Http::HeaderUtility::getAllOfHeaderAsString(headers, name_);
        bool isPresentMatch = (value_.length() == 0 && !secret_);

        if (isPresentMatch)
          matches = header_value.result().has_value();
        else {
          // Value match, update secret?
          if (secret_) {
            auto* secret_value = secret_->value();
            if (secret_value)
              match_value = secret_value;
            else if (value_.length() == 0)
              ENVOY_LOG(info, "Cilium HeaderMatch missing SDS secret value for header {}", name_);
          }
          if (header_value.result().has_value())
            matches = (header_value.result().value() == *match_value);
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
            if (isPresentMatch) {
              // presence match failed, nothing to do
              return true;
            }
            if (!header_value.result().has_value())
              return true; // nothing to remove

            // Remove the header with an incorrect value
            headers.remove(name_);
            logRejected(log_entry, header_value.result().value());
            return true;
          case cilium::HeaderMatch::REPLACE_ON_MISMATCH:
            // Log the wrong value as rejected, if the header existed with a wrong value
            if (header_value.result().has_value())
              logRejected(log_entry, header_value.result().value());
            // Set the expected value
            ENVOY_LOG(debug, "secret replacing header {}={}", name_, *match_value);
            headers.setCopy(name_, *match_value);
            // Log the expected value as missing
            logMissing(log_entry, *match_value);
            return true;
          }
        }
        IS_ENVOY_BUG("HeaderMatch reached unreachable return");
        return true;
      }

      const Http::LowerCaseString name_;
      std::string value_;
      cilium::HeaderMatch::MatchAction match_action_;
      cilium::HeaderMatch::MismatchAction mismatch_action_;
      SecretWatcherPtr secret_;
    };

  public:
    HttpNetworkPolicyRule(const NetworkPolicyMap& parent,
                          const cilium::HttpNetworkPolicyRule& rule) {
      ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
      headers_.reserve(rule.headers().size());
      for (const auto& header : rule.headers()) {
        headers_.emplace_back(std::make_unique<Http::HeaderUtility::HeaderData>(header));
        const auto& header_data = *headers_.back();
        ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={}",
                  header_data.name_.get(),
                  header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Range
                      ? fmt::format("[{}-{})", header_data.range_.start(), header_data.range_.end())
                  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Value
                      ? "<VALUE>"
                  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Present
                      ? "<PRESENT>"
                  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Regex
                      ? "<REGEX>"
                      : "<UNKNOWN>");
      }
      header_matches_.reserve(rule.header_matches().size());
      for (const auto& config : rule.header_matches()) {
        header_matches_.emplace_back(parent, config);
        const auto& header_match = header_matches_.back();
        ENVOY_LOG(trace,
                  "Cilium L7 HttpNetworkPolicyRule(): HeaderMatch {}={} (match: {}, mismatch: {})",
                  header_match.name_.get(),
                  header_match.secret_ ? fmt::format("<SECRET {}>", header_match.secret_->name())
                  : header_match.value_.length() > 0 ? header_match.value_
                                                     : "<PRESENT>",
                  header_match.match_action_, header_match.mismatch_action_);
      }
    }

    bool Matches(const Envoy::Http::RequestHeaderMap& headers) const {
      // Empty set matches any headers.
      return Http::HeaderUtility::matchHeaders(headers, headers_);
    }

    // Should only be called after 'Matches' returns 'true'.
    // Returns 'true' if matching can continue
    bool HeaderMatches(Envoy::Http::RequestHeaderMap& headers,
                       Cilium::AccessLog::Entry& log_entry) const {
      bool accepted = true;
      for (const auto& header_match : header_matches_) {
        if (!header_match.Matches(headers, log_entry)) {
          accepted = false;
        }
      }
      return accepted;
    }

    std::vector<Http::HeaderUtility::HeaderDataPtr> headers_; // Allowed if empty.
    std::vector<HeaderMatch> header_matches_;
  };

  class L7NetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
  public:
    L7NetworkPolicyRule(const cilium::L7NetworkPolicyRule& rule) : name_(rule.name()) {
      for (const auto& matcher : rule.metadata_rule()) {
        ENVOY_LOG(trace, "Cilium L7NetworkPolicyRule() metadata_rule: {}", matcher.DebugString());
        metadata_matchers_.emplace_back(matcher);
        matchers_.emplace_back(matcher);
      }
    }

    bool matches(const envoy::config::core::v3::Metadata& metadata) const {
      // All matchers must be satisfied for the rule to match
      int i = 0; // Only used for trace-level debug
      for (const auto& metadata_matcher : metadata_matchers_) {
        ENVOY_LOG(trace,
                  "L7NetworkPolicyRule::matches(): checking rule {} against "
                  "metadata {}",
                  matchers_[i++].DebugString(), metadata.DebugString());
        if (!metadata_matcher.match(metadata)) {
          return false;
        }
      }
      return true;
    }

    std::string name_;

  private:
    std::vector<Envoy::Matchers::MetadataMatcher> metadata_matchers_;
    std::vector<envoy::type::matcher::v3::MetadataMatcher> matchers_;
  };

  class PortNetworkPolicyRule : public PortPolicy, public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRule(const NetworkPolicyMap& parent, const cilium::PortNetworkPolicyRule& rule)
        : name_(rule.name()), l7_proto_(rule.l7_proto()) {
      for (const auto& remote : rule.remote_policies()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {} by rule: {}",
                  remote, rule.DebugString());
        allowed_remotes_.emplace(remote);
      }
      if (rule.has_downstream_tls_context()) {
        auto config = rule.downstream_tls_context();
        server_context_ = std::make_unique<DownstreamTLSContext>(parent, config);
      }
      if (rule.has_upstream_tls_context()) {
        auto config = rule.upstream_tls_context();
        client_context_ = std::make_unique<UpstreamTLSContext>(parent, config);
      }
      for (const auto& sni : rule.server_names()) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing SNI {} by rule {}", sni,
                  name_);
        allowed_snis_.emplace(sni);
      }
      if (rule.has_http_rules()) {
        for (const auto& http_rule : rule.http_rules().http_rules()) {
          if (http_rule.header_matches_size() > 0) {
            have_header_matches_ = true;
          }
          http_rules_.emplace_back(parent, http_rule);
        }
      }
      if (l7_proto_.length() > 0 && rule.has_l7_rules()) {
        const auto& ruleset = rule.l7_rules();
        for (const auto& l7_rule : ruleset.l7_deny_rules()) {
          l7_deny_rules_.emplace_back(l7_rule);
        }
        for (const auto& l7_rule : ruleset.l7_allow_rules()) {
          l7_allow_rules_.emplace_back(l7_rule);
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

    bool Matches(absl::string_view sni, uint64_t remote_id) const override {
      // sni must match if we have any
      if (allowed_snis_.size() > 0) {
        if (sni.length() == 0) {
          return false;
        }
        auto search = allowed_snis_.find(sni);
        if (search == allowed_snis_.end()) {
          return false;
        }
      }
      return Matches(remote_id);
    }

    bool Matches(uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers,
                 Cilium::AccessLog::Entry& log_entry) const {
      if (!Matches(remote_id)) {
        return false;
      }
      if (http_rules_.size() > 0) {
        bool matched = false;
        for (const auto& rule : http_rules_) {
          if (rule.Matches(headers)) {
            // Return on the first match if no rules have header actions
            if (!have_header_matches_) {
              return true;
            }
            // orherwise evaluate all rules to run all the header actions,
            // and remember if any of them matched
            if (rule.HeaderMatches(headers, log_entry)) {
              matched = true;
            }
          }
        }
        return matched;
      }
      // Empty set matches any payload
      return true;
    }

    // PortPolicy
    bool useProxylib(std::string& l7_proto) const override {
      if (l7_proto_.length() > 0) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::useProxylib(): returning {}",
                  l7_proto_);
        l7_proto = l7_proto_;
        return true;
      }
      return false;
    }

    // Envoy Metadata matcher
    bool allowed(const envoy::config::core::v3::Metadata& metadata) const override {
      for (const auto& rule : l7_deny_rules_) {
        if (rule.matches(metadata)) {
          ENVOY_LOG(trace,
                    "Cilium L7 PortNetworkPolicyRules::allowed(): DENY due to "
                    "a matching deny rule {}",
                    rule.name_);
          return false; // request is denied if any deny rule matches
        }
      }
      if (l7_allow_rules_.size() > 0) {
        for (const auto& rule : l7_allow_rules_) {
          if (rule.matches(metadata)) {
            ENVOY_LOG(trace,
                      "Cilium L7 PortNetworkPolicyRules::allowed(): ALLOW due "
                      "to a matching allow rule {}",
                      rule.name_);
            return true;
          }
        }
        ENVOY_LOG(trace,
                  "Cilium L7 PortNetworkPolicyRules::allowed(): DENY due to "
                  "all {} allow rules mismatching",
                  l7_allow_rules_.size());
        return false;
      }
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::allowed(): default ALLOW "
                       "due to no allow rules");
      return true; // allowed by default
    }

    const Ssl::ContextConfig& getServerTlsContextConfig() const override {
      return server_context_->getTlsContextConfig();
    }
    Ssl::ContextSharedPtr getServerTlsContext() const override {
      if (server_context_)
        return server_context_->getTlsContext();
      return nullptr;
    }

    const Ssl::ContextConfig& getClientTlsContextConfig() const override {
      return client_context_->getTlsContextConfig();
    }
    Ssl::ContextSharedPtr getClientTlsContext() const override {
      if (client_context_)
        return client_context_->getTlsContext();
      return nullptr;
    }

    std::string name_;
    DownstreamTLSContextPtr server_context_;
    UpstreamTLSContextPtr client_context_;
    absl::flat_hash_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
    // Use std::less<> to allow heterogeneous lookups (with string_view).
    std::set<std::string, std::less<>> allowed_snis_; // All SNIs allowed if empty.
    std::vector<HttpNetworkPolicyRule>
        http_rules_; // Allowed if empty, but remote is checked first.
    bool have_header_matches_{false};
    std::string l7_proto_{};
    std::vector<L7NetworkPolicyRule> l7_allow_rules_;
    std::vector<L7NetworkPolicyRule> l7_deny_rules_;
  };
  using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

  class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRules(const NetworkPolicyMap& parent,
                           const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
      if (rules.size() == 0) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow "
                         "everything.");
      }
      for (const auto& it : rules) {
        rules_.emplace_back(std::make_shared<PortNetworkPolicyRule>(parent, it));
        if (rules_.back()->have_header_matches_) {
          have_header_matches_ = true;
        }
      }
    }

    bool Matches(uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers,
                 Cilium::AccessLog::Entry& log_entry) const {
      // Empty set matches any payload from anyone
      if (rules_.size() == 0) {
        return true;
      }
      bool matched = false;
      for (const auto& rule : rules_) {
        if (rule->Matches(remote_id, headers, log_entry)) {
          matched = true;
          // Short-circuit on the first match if no rules have HeaderMatches
          if (!have_header_matches_) {
            break;
          }
        }
      }
      return matched;
    }

    const PortPolicyConstSharedPtr findPortPolicy(uint64_t remote_id) const {
      // Empty set matches any payload from anyone
      if (rules_.size() == 0) {
        return allowPortNetworkPolicyRule;
      }
      for (const auto& rule : rules_) {
        if (rule->Matches(remote_id)) {
          return rule;
        }
      }
      return nullptr;
    }

    std::vector<PortNetworkPolicyRuleConstSharedPtr> rules_; // Allowed if empty.
    bool have_header_matches_{false};
  };

  class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicy(const NetworkPolicyMap& parent,
                      const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
      for (const auto& it : rules) {
        // Only TCP supported for HTTP
        if (it.protocol() == envoy::config::core::v3::SocketAddress::TCP) {
          // Port may be zero, which matches any port.
          uint16_t port = it.port();
          // End port may be zero, which means no range
          uint16_t end_port = it.end_port();
          if (end_port < port) {
            if (end_port != 0) {
              throw EnvoyException(fmt::format(
                  "PortNetworkPolicy: Invalid port range, end port is less than port {}-{}", port,
                  end_port));
            }
            end_port = port;
          }
          if (port == 0 && end_port > 0) {
            throw EnvoyException(fmt::format(
                "PortNetworkPolicy: Invalid port range including the wildcard zero port {}-{}",
                port, end_port));
          }
          ENVOY_LOG(trace,
                    "Cilium L7 PortNetworkPolicy(): installing TCP policy for "
                    "port range {}-{}",
                    port, end_port);
          if (!rules_
                   .emplace(std::make_pair(port, end_port),
                            PortNetworkPolicyRules(parent, it.rules()))
                   .second) {
            if (port == end_port) {
              throw EnvoyException(
                  fmt::format("PortNetworkPolicy: Duplicate port number {}", port));
            } else {
              throw EnvoyException(
                  fmt::format("PortNetworkPolicy: Overlapping port range {}-{}", port, end_port));
            }
          }
        } else {
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
        }
      }
    }

    typedef absl::btree_map<std::pair<uint16_t, uint16_t>, PortNetworkPolicyRules, PortRangeCompare>
        PolicyMap;

    PolicyMap::const_iterator find(uint16_t port) const {
      std::pair<uint16_t, uint16_t> p = {port, port};
      auto it = rules_.find(p);
      if (it != rules_.end()) {
        const auto& range = it->first;
        if (port >= range.first && port <= range.second) {
          return it;
        }
      }
      return rules_.end();
    }

    bool Matches(uint16_t port, uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers,
                 Cilium::AccessLog::Entry& log_entry) const {
      auto it = find(port);
      if (it != rules_.end()) {
        if (it->second.Matches(remote_id, headers, log_entry)) {
          return true;
        }
      }
      // Check for any rules that wildcard the port
      // Note: Wildcard port makes no sense for an L7 policy, but the policy
      // could be a L3/L4 policy as well.
      it = find(0);
      if (it != rules_.end()) {
        if (it->second.Matches(remote_id, headers, log_entry)) {
          return true;
        }
      }
      return false;
    }

    const PortPolicyConstSharedPtr findPortPolicy(uint16_t port, uint64_t remote_id) const {
      auto it = find(port);
      if (it != rules_.end()) {
        return it->second.findPortPolicy(remote_id);
      }
      // Check for any rules that wildcard the port
      // Note: Wildcard port makes no sense for an L7 policy, but the policy
      // could be a L3/L4 policy as well.
      it = find(0);
      if (it != rules_.end()) {
        return it->second.findPortPolicy(remote_id);
      }
      return nullptr;
    }

    PolicyMap rules_;
  };

public:
  bool Allowed(bool ingress, uint16_t port, uint64_t remote_id,
               Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const override {
    return ingress ? ingress_.Matches(port, remote_id, headers, log_entry)
                   : egress_.Matches(port, remote_id, headers, log_entry);
  }

  const PortPolicyConstSharedPtr findPortPolicy(bool ingress, uint16_t port,
                                                uint64_t remote_id) const override {
    return ingress ? ingress_.findPortPolicy(port, remote_id)
                   : egress_.findPortPolicy(port, remote_id);
  }

  bool useProxylib(bool ingress, uint16_t port, uint64_t remote_id,
                   std::string& l7_proto) const override {
    const auto& port_policy = findPortPolicy(ingress, port, remote_id);
    if (port_policy != nullptr) {
      return port_policy->useProxylib(l7_proto);
    }
    return false;
  }

  const std::string& conntrackName() const override { return conntrack_map_name_; }

  uint32_t getEndpointID() const override { return endpoint_id_; }

  const IPAddressPair& getEndpointIPs() const override { return endpoint_ips_; }

public:
  std::string conntrack_map_name_;
  uint32_t endpoint_id_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;
  const IPAddressPair endpoint_ips_;

private:
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

// Common base constructor
// This is used directly for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context)
    : tls_map_(context.threadLocal()),
      local_ip_str_(context.localInfo().address()->ip()->addressAsString()),
      name_(fmt::format("cilium.policymap.{}.{}.", local_ip_str_, ++instance_id_)),
      scope_(context.serverScope().createScope(name_)),
      init_target_(fmt::format("Cilium Network Policy subscription start"),
                   [this]() { subscription_->start({}); }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context.getServerFactoryContext(),
              context.getTransportSocketFactoryContext().sslContextManager(), *scope_,
              context.getServerFactoryContext().clusterManager(),
              context.getTransportSocketFactoryContext().stats(),
              context.messageValidationContext().dynamicValidationVisitor())),
      is_sidecar_(context.localInfo().nodeName().rfind("sidecar~", 0) == 0) {
  // Use listener init manager for the first initialization
  transport_factory_context_->setInitManager(context.initManager());
  context.initManager().add(init_target_);

  ENVOY_LOG(trace, "NetworkPolicyMap({}) created.", name_);
  tls_map_.set([&](Event::Dispatcher&) { return std::make_shared<ThreadLocalPolicyMap>(); });
}

// This is used in production
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context,
                                   Cilium::CtMapSharedPtr& ct)
    : NetworkPolicyMap(context) {
  ctmap_ = ct;
}

// Both subscribe() call and subscription_->start() use
// shared_from_this(), which cannot be called before a shared
// pointer is formed by the caller of the constructor, hence this
// can't be called from the constructor!
void NetworkPolicyMap::startSubscription(Server::Configuration::FactoryContext& context) {
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicy", context.localInfo(),
                            context.clusterManager(), context.mainThreadDispatcher(),
                            context.api().randomGenerator(), *scope_, *this,
                            std::make_shared<NetworkPolicyDecoder>());
}

static const std::shared_ptr<const PolicyInstanceImpl> null_instance_impl{nullptr};

const std::shared_ptr<const PolicyInstanceImpl>&
NetworkPolicyMap::GetPolicyInstanceImpl(const std::string& endpoint_ip) const {
  auto it = tls_map_->policies_.find(endpoint_ip);
  if (it == tls_map_->policies_.end()) {
    return null_instance_impl;
  }
  return it->second;
}

const PolicyInstanceConstSharedPtr
NetworkPolicyMap::GetPolicyInstance(const std::string& endpoint_ip) const {
  return GetPolicyInstanceImpl(endpoint_ip);
}

void NetworkPolicyMap::pause() {
  auto sub = dynamic_cast<Config::GrpcSubscriptionImpl*>(subscription_.get());
  if (sub) {
    resume_ = sub->pause();
  }
}

void NetworkPolicyMap::resume() { resume_.reset(); }

void NetworkPolicyMap::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  ENVOY_LOG(debug, "NetworkPolicyMap::onConfigUpdate({}), {} resources, version: {}", name_,
            resources.size(), version_info);

  absl::flat_hash_set<std::string> keeps;
  absl::flat_hash_set<std::string> ct_maps_to_keep;

  std::string version_name = fmt::format("NetworkPolicyMap manager for version {}", version_info);

  // Init manager for this version update.
  // For the first initialization the listener's init manager is used.
  // Setting the member here releases any previous manager as well.
  version_init_manager_ = std::make_shared<Init::ManagerImpl>(version_name);

  // Set the init manager to use via the transport factory context
  // Use the local init manager after the first initialization
  if (version_init_target_)
    transport_factory_context_->setInitManager(*version_init_manager_);

  // Collect a shared vector of policies to be added
  auto to_be_added = std::make_shared<std::vector<std::shared_ptr<PolicyInstanceImpl>>>();
  try {
    for (const auto& resource : resources) {
      const auto& config = dynamic_cast<const cilium::NetworkPolicy&>(resource.get().resource());
      ENVOY_LOG(debug,
                "Received Network Policy for endpoint {} in onConfigUpdate() "
                "version {}",
                config.endpoint_id(), version_info);
      if (config.endpoint_ips().size() == 0) {
        throw EnvoyException("Network Policy has no endpoint ips");
      }
      for (const auto& endpoint_ip : config.endpoint_ips()) {
        keeps.insert(endpoint_ip);
      }
      ct_maps_to_keep.insert(config.conntrack_map_name());

      // First find the old config to figure out if an update is needed.
      const uint64_t new_hash = MessageUtil::hash(config);
      const auto& old_policy = GetPolicyInstanceImpl(config.endpoint_ips()[0]);
      if (old_policy && old_policy->hash_ == new_hash &&
          Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
        ENVOY_LOG(trace, "New policy is equal to old one, not updating.");
        continue;
      }

      // May throw
      to_be_added->emplace_back(std::make_shared<PolicyInstanceImpl>(*this, new_hash, config));
    }
  } catch (const EnvoyException& e) {
    ENVOY_LOG(debug, "NetworkPolicy update for version {} failed: {}", version_info, e.what());

    // Allow main (Listener) init to continue after exceptions
    init_target_.ready();

    throw; // re-throw
  }

  // Collect a shared vector of policy names to be removed
  auto to_be_deleted = std::make_shared<std::vector<std::string>>();
  // Collect a shared vector of conntrack maps to close
  auto cts_to_be_closed = std::make_shared<absl::flat_hash_set<std::string>>();
  const auto& policies = tls_map_->policies_;
  for (auto& pair : policies) {
    if (keeps.find(pair.first) == keeps.end()) {
      to_be_deleted->emplace_back(pair.first);
    }
    // insert conntrack map names we don't want to keep and that have not been
    // already inserted.
    auto& ct_map_name = pair.second->conntrack_map_name_;
    if (ct_maps_to_keep.find(ct_map_name) == ct_maps_to_keep.end() &&
        cts_to_be_closed->find(ct_map_name) == cts_to_be_closed->end()) {
      ENVOY_LOG(debug, "Closing conntrack map {}", ct_map_name);
      cts_to_be_closed->insert(ct_map_name);
    }
  }

  // Allow main (Listener) init to continue before workers are started.
  init_target_.ready();

  // Create a local init target to track network policy updates on worker threads.
  // This is added to the local init manager below in order to wait for all worker
  // threads to have applied policy updates before NPDS ACK is sent.
  // First setting of this also causes future updates to use the local init manager.
  version_init_target_ = std::make_shared<Init::TargetImpl>(version_name, []() {});

  // Skip pausing if nothing to be done
  if (to_be_added->size() == 0 && to_be_deleted->size() == 0 && cts_to_be_closed->size() == 0) {
    ENVOY_LOG(trace, "Skipping empty or duplicate policy update.");
  } else {
    // pause the subscription until the worker threads are done. No throws after this!
    // local init target is marked ready when all workers have updated.
    version_init_manager_->add(*version_init_target_);
    ENVOY_LOG(trace, "Pausing NPDS subscription");
    pause();

    // 'this' may be already deleted when the worker threads get to execute the
    // updates. Manage this by taking a shared_ptr on 'this' for the duration of
    // the posted lambda.
    std::shared_ptr<NetworkPolicyMap> shared_this = shared_from_this();

    // Resume subscription via an Init::Watcher when fully initialized
    // This Watcher needs to be a member so that it exists after this function returns.
    // It needs to be dynamically allocated so that we can initialize a new watcher for each
    // network policy version.
    // Since this is a member it must not hold a reference to the map to avoid a circular
    // reference; so use a weak pointer instead.
    // Setting the member here releases any previous watcher as well.
    std::weak_ptr<NetworkPolicyMap> weak_this = shared_this;
    version_init_watcher_ = std::make_shared<Init::WatcherImpl>(version_name, [weak_this]() {
      if (std::shared_ptr<NetworkPolicyMap> shared_this = weak_this.lock()) {
        // resume subscription when fully initialized
        ENVOY_LOG(trace, "Resuming NPDS subscription");
        shared_this->resume();
      } else {
        ENVOY_LOG_MISC(debug, "NetworkPolicyMap expired on watcher completion!");
      }
    });

    // Execute changes on all threads.
    tls_map_.runOnAllThreads(
        [to_be_added, to_be_deleted, version_info](OptRef<ThreadLocalPolicyMap> npmap) {
          if (!npmap.has_value()) {
            ENVOY_LOG(debug,
                      "Cilium L7 NetworkPolicyMap::onConfigUpdate(): npmap has no value "
                      "for version {}",
                      version_info);
            return;
          }
          ENVOY_LOG(trace,
                    "Cilium L7 NetworkPolicyMap::onConfigUpdate(): Starting "
                    "updates on the next thread for version {}",
                    version_info);
          for (const auto& policy_name : *to_be_deleted) {
            ENVOY_LOG(trace, "Cilium deleting removed network policy for endpoint {}", policy_name);
            npmap->policies_.erase(policy_name);
          }
          for (const auto& new_policy : *to_be_added) {
            for (const auto& endpoint_ip : new_policy->policy_proto_.endpoint_ips()) {
              ENVOY_LOG(trace, "Cilium updating network policy for endpoint {}", endpoint_ip);
              npmap->policies_[endpoint_ip] = new_policy;
            }
          }
        },
        // All threads have executed updates, delete old cts and mark the local init target ready.
        [shared_this, cts_to_be_closed]() {
          if (shared_this->ctmap_ && cts_to_be_closed->size() > 0) {
            shared_this->ctmap_->closeMaps(cts_to_be_closed);
          }
          shared_this->version_init_target_->ready();
        });
    // Initialize SDS secrets, the watcher callback above will be called after all threads have
    // updated policies and secrets have been fetched, or timeout (15 seconds) hits.
    version_init_manager_->initialize(*version_init_watcher_);
  }

  // Remove the local init manager from the transport factory context
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnull-dereference"
  transport_factory_context_->setInitManager(*static_cast<Init::Manager*>(nullptr));
#pragma clang diagnostic pop
}

void NetworkPolicyMap::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                                            const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(debug, "Network Policy Update failed, keeping existing policy.");
}

void NetworkPolicyMap::runAfterAllThreads(std::function<void()> cb) const {
  const_cast<NetworkPolicyMap*>(this)->tls_map_.runOnAllThreads([](OptRef<ThreadLocalPolicyMap>) {},
                                                                cb);
}

PolicyInstanceConstSharedPtr NetworkPolicyMap::AllowAllEgressPolicy =
    std::make_shared<AllowAllEgressPolicyInstanceImpl>();

} // namespace Cilium
} // namespace Envoy
