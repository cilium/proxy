#include "cilium/network_policy.h"

#include <algorithm>
#include <string>

#include "envoy/type/matcher/v3/metadata.pb.h"

#include "source/common/common/matchers.h"
#include "source/common/config/utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h"

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "cilium/grpc_subscription.h"
#include "cilium/ipcache.h"
#include "cilium/secret_watcher.h"

namespace Envoy {
namespace Cilium {

uint64_t NetworkPolicyMap::instance_id_ = 0;

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

class HeaderMatch : public Logger::Loggable<Logger::Id::config> {
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
  bool allowed(Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
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
        headers.setCopy(name_, *match_value);
        // Log the expected value as missing
        logMissing(log_entry, *match_value);
        return true;
      }
    }
    IS_ENVOY_BUG("HeaderMatch reached unreachable return");
    return true;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- name: \"").append(name_.get()).append("\"\n");
    if (value_.length() > 0) {
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
  SecretWatcherPtr secret_;
};

class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  HttpNetworkPolicyRule(const NetworkPolicyMap& parent, const cilium::HttpNetworkPolicyRule& rule) {
    ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
    headers_.reserve(rule.headers().size());
    for (const auto& header : rule.headers()) {
      headers_.emplace_back(std::make_unique<Http::HeaderUtility::HeaderData>(
          header, parent.transportFactoryContext().serverFactoryContext()));
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

  bool allowed(const Envoy::Http::RequestHeaderMap& headers) const {
    // Empty set matches any headers.
    return Http::HeaderUtility::matchHeaders(headers, headers_);
  }

  // Should only be called after 'allowed' returns 'true'.
  // Returns 'true' if matching can continue
  bool HeaderMatches(Envoy::Http::RequestHeaderMap& headers,
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
    if (headers_.size() > 0) {
      if (first) {
        first = false;
        res.append(indent - 2, ' ').append("- ");
      } else {
        res.append(indent, ' ');
      }
      res.append("headers:\n");
      for (auto& h : headers_) {
        res.append(indent, ' ').append("- name: \"").append(h->name_.get()).append("\"\n");
        switch (h->header_match_type_) {
        case Http::HeaderUtility::HeaderMatchType::Value:
          res.append(indent + 2, ' ').append("value: \"").append(h->value_).append("\"\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::Regex:
          res.append(indent + 2, ' ').append("regex: ").append("<hidden>\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::Range:
          res.append(indent + 2, ' ')
              .append("range: ")
              .append(fmt::format("[{}-{})\n", h->range_.start(), h->range_.end()));
          break;
        case Http::HeaderUtility::HeaderMatchType::Present:
          res.append(indent + 2, ' ')
              .append("present: ")
              .append(h->present_ ? "true\n" : "false\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::Prefix:
          res.append(indent + 2, ' ').append("prefix: \"").append(h->value_).append("\"\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::Suffix:
          res.append(indent + 2, ' ').append("suffix: \"").append(h->value_).append("\"\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::Contains:
          res.append(indent + 2, ' ').append("contains: \"").append(h->value_).append("\"\n");
          break;
        case Http::HeaderUtility::HeaderMatchType::StringMatch:
          res.append(indent + 2, ' ').append("string_match: ").append("<hidden>\n");
          break;
        }
        if (h->invert_match_) {
          res.append(indent + 2, ' ').append("invert_match: true\n");
        }
        if (h->treat_missing_as_empty_) {
          res.append(indent + 2, ' ').append("treat_missing_as_empty: true\n");
        }
      }
    }
    if (header_matches_.size() > 0) {
      if (first) {
        first = false;
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

class L7NetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  L7NetworkPolicyRule(const NetworkPolicyMap& parent, const cilium::L7NetworkPolicyRule& rule)
      : name_(rule.name()) {
    for (const auto& matcher : rule.metadata_rule()) {
      metadata_matchers_.emplace_back(matcher,
                                      parent.transportFactoryContext().serverFactoryContext());
      matchers_.emplace_back(matcher);
    }
  }

  bool matches(const envoy::config::core::v3::Metadata& metadata) const {
    // All matchers must be satisfied for the rule to match
    for (const auto& metadata_matcher : metadata_matchers_) {
      if (!metadata_matcher.match(metadata)) {
        return false;
      }
    }
    return true;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- name: \"").append(name_).append("\"\n");
  }

  std::string name_;

private:
  std::vector<Envoy::Matchers::MetadataMatcher> metadata_matchers_;
  std::vector<envoy::type::matcher::v3::MetadataMatcher> matchers_;
};

class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRule(const NetworkPolicyMap& parent, const cilium::PortNetworkPolicyRule& rule)
      : name_(rule.name()), deny_(rule.deny()), l7_proto_(rule.l7_proto()) {
    // Deny rules can not be short circuited, i.e., if any deny rules are present, then all
    // rules must be evaluated even if one would allow
    can_short_circuit_ = !deny_;
    for (const auto& remote : rule.remote_policies()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} remote {} by rule: {}",
                deny_ ? "Denying" : "Allowing", remote, name_);
      remotes_.emplace(remote);
    }
    // TODO: Remove deprecated_remote_policies_64 when Cilium 1.14 is no longer supported
    for (const auto& remote : rule.deprecated_remote_policies_64()) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): {} remote {} by rule: {}",
                deny_ ? "Denying" : "Allowing", remote, name_);
      remotes_.emplace(remote);
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
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing SNI {} by rule {}", sni, name_);
      allowed_snis_.emplace(sni);
    }
    if (rule.has_http_rules()) {
      for (const auto& http_rule : rule.http_rules().http_rules()) {
        if (http_rule.header_matches_size() > 0) {
          can_short_circuit_ = false;
        }
        http_rules_.emplace_back(parent, http_rule);
      }
    }
    if (l7_proto_.length() > 0 && rule.has_l7_rules()) {
      const auto& ruleset = rule.l7_rules();
      for (const auto& l7_rule : ruleset.l7_deny_rules()) {
        l7_deny_rules_.emplace_back(parent, l7_rule);
      }
      for (const auto& l7_rule : ruleset.l7_allow_rules()) {
        l7_allow_rules_.emplace_back(parent, l7_rule);
      }
    }
  }

  bool allowed(uint32_t remote_id, bool& denied) const {
    // Remote ID must match if we have any.
    if (remotes_.size() > 0) {
      auto match = remotes_.find(remote_id);
      if (match != remotes_.end()) {
        // remote ID matched
        if (deny_) {
          // Explicit deny
          denied = true;
          return false;
        }
        // Explicit allow
        return true;
      }
      // Not found, not allowed, but also not explicitly denied
      return false;
    }
    // Allow rules allow by default when remotes_ is empty, deny rules do not
    if (deny_) {
      denied = true;
      return false;
    }
    return true;
  }

  bool allowed(uint32_t remote_id, absl::string_view sni, bool& denied) const {
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
    return allowed(remote_id, denied);
  }

  bool allowed(uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry, bool& denied) const {
    if (!allowed(remote_id, denied)) {
      return false;
    }
    if (http_rules_.size() > 0) {
      bool allowed = false;
      for (const auto& rule : http_rules_) {
        if (rule.allowed(headers)) {
          // Return on the first match if no rules have header actions
          if (can_short_circuit_) {
            allowed = true;
            break;
          }
          // orherwise evaluate all rules to run all the header actions,
          // and remember if any of them matched
          if (rule.HeaderMatches(headers, log_entry)) {
            allowed = true;
          }
        }
      }
      return allowed;
    }
    // Empty set matches any payload
    return true;
  }

  bool useProxylib(uint32_t remote_id, std::string& l7_proto) const {
    bool denied = false;
    if (!allowed(remote_id, denied)) {
      return false;
    }
    if (l7_proto_.length() > 0) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::useProxylib(): returning {}", l7_proto_);
      l7_proto = l7_proto_;
      return true;
    }
    return false;
  }

  // Envoy Metadata matcher, called after deny has already been checked for
  bool allowed(uint32_t remote_id, const envoy::config::core::v3::Metadata& metadata,
               bool& denied) const {
    if (!allowed(remote_id, denied)) {
      return false;
    }
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

  Ssl::ContextSharedPtr getServerTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const {
    bool denied = false;
    if (server_context_ && allowed(remote_id, denied)) {
      *config = &server_context_->getTlsContextConfig();
      return server_context_->getTlsContext();
    }
    return nullptr;
  }

  Ssl::ContextSharedPtr getClientTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const {
    bool denied = false;
    if (client_context_ && allowed(remote_id, denied)) {
      *config = &client_context_->getTlsContextConfig();
      return client_context_->getTlsContext();
    }
    return nullptr;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- remotes: [");
    int count = 0;
    for (auto remote : remotes_) {
      if (count++ > 0) {
        res.append(",");
      }
      res.append(fmt::format("{}", remote));
    }
    res.append("]\n");

    if (name_.length() > 0) {
      res.append(indent, ' ').append("name: \"").append(name_).append("\"\n");
    }
    if (!can_short_circuit_) {
      res.append(indent, ' ').append("can_short_circuit: false\n");
    }
    if (deny_) {
      res.append(indent, ' ').append("deny: true\n");
    }

    if (allowed_snis_.size() > 0) {
      res.append(indent, ' ').append("allowed_snis: [");
      int count = 0;
      for (auto& sni : allowed_snis_) {
        if (count++ > 0) {
          res.append(",");
        }
        res.append(fmt::format("\"{}\"", sni));
      }
      res.append("]\n");
    }

    if (http_rules_.size() > 0) {
      res.append(indent, ' ').append("http_rules:\n");
      for (auto& rule : http_rules_) {
        rule.toString(indent + 2, res);
      }
    }

    if (l7_proto_.length() > 0) {
      res.append(indent, ' ').append("l7_proto: \"").append(l7_proto_).append("\"\n");
    }
    if (l7_allow_rules_.size() > 0) {
      res.append(indent, ' ').append("l7_allow_rules:\n");
      for (auto& rule : l7_allow_rules_) {
        rule.toString(indent + 2, res);
      }
    }
    if (l7_deny_rules_.size() > 0) {
      res.append(indent, ' ').append("l7_deny_rules:\n");
      for (auto& rule : l7_deny_rules_) {
        rule.toString(indent + 2, res);
      }
    }
  }

  std::string name_;
  DownstreamTLSContextPtr server_context_;
  UpstreamTLSContextPtr client_context_;
  bool can_short_circuit_{true};
  bool deny_;
  absl::btree_set<uint32_t> remotes_;
  // Use std::less<> to allow heterogeneous lookups (with string_view).
  std::set<std::string, std::less<>> allowed_snis_; // All SNIs allowed if empty.
  std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
  std::string l7_proto_{};
  std::vector<L7NetworkPolicyRule> l7_allow_rules_;
  std::vector<L7NetworkPolicyRule> l7_deny_rules_;
};
using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRules() {}
  PortNetworkPolicyRules(const NetworkPolicyMap& parent,
                         const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
    if (rules.size() == 0) {
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow "
                       "everything.");
    }
    for (const auto& it : rules) {
      rules_.emplace_back(std::make_shared<PortNetworkPolicyRule>(parent, it));
      if (!rules_.back()->can_short_circuit_) {
        can_short_circuit_ = false;
      }
    }
  }

  bool allowed(uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry, bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.size() == 0) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(remote_id, headers, log_entry, denied)) {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): ALLOWED");
        allowed = true;
        // Short-circuit on the first match if no rules have HeaderMatches or if deny rules do not
        // exist
        if (can_short_circuit_) {
          break;
        }
      }
    }
    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): returning {}", allowed && !denied);
    return allowed && !denied;
  }

  bool allowed(uint32_t remote_id, absl::string_view sni, bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.size() == 0) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(remote_id, sni, denied)) {
        allowed = true;
        // Short-circuit on the first match if no rules have HeaderMatches or if deny rules do not
        // exist
        if (can_short_circuit_) {
          break;
        }
      }
    }
    return allowed && !denied;
  }

  bool useProxylib(uint32_t remote_id, std::string& l7_proto) const {
    for (const auto& rule : rules_) {
      if (rule->useProxylib(remote_id, l7_proto)) {
        return true;
      }
    }
    return false;
  }

  bool allowed(uint32_t remote_id, const envoy::config::core::v3::Metadata& metadata,
               bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.size() == 0) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(remote_id, metadata, denied)) {
        allowed = true;
        // Short-circuit on the first match if no rules have HeaderMatches or if deny rules do not
        // exist
        if (can_short_circuit_) {
          break;
        }
      }
    }
    return allowed && !denied;
  }

  Ssl::ContextSharedPtr getServerTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const {
    for (const auto& rule : rules_) {
      Ssl::ContextSharedPtr server_context = rule->getServerTlsContext(remote_id, config);
      if (server_context)
        return server_context;
    }
    return nullptr;
  }

  Ssl::ContextSharedPtr getClientTlsContext(uint32_t remote_id,
                                            const Ssl::ContextConfig** config) const {
    for (const auto& rule : rules_) {
      Ssl::ContextSharedPtr client_context = rule->getClientTlsContext(remote_id, config);
      if (client_context)
        return client_context;
    }
    return nullptr;
  }

  void toString(int indent, std::string& res) const {
    res.append(indent - 2, ' ').append("- rules:\n");
    for (auto& rule : rules_) {
      rule->toString(indent + 2, res);
    }
    if (!can_short_circuit_) {
      res.append(indent, ' ').append(fmt::format("can_short_circuit: false\n"));
    }
  }

  std::vector<PortNetworkPolicyRuleConstSharedPtr> rules_; // Allowed if empty.
  bool can_short_circuit_{true};
};

// end port is zero on lookup!
PortPolicy::PortPolicy(const PolicyMap& map, const RulesList& wildcard_rules, uint16_t port)
    : map_(map), wildcard_rules_(wildcard_rules), port_rules_(map_.find({port, port})) {}

// for_range is used for policy lookups, so it will need to check both port-specific and
// wildcard-port rules, as either of them could contain rules that must be evaluated (i.e., deny
// or header match rules with side effects).
bool PortPolicy::for_range(
    std::function<bool(const PortNetworkPolicyRules&, bool& denied)> allowed) const {
  bool allow = false;
  bool denied = false;
  if (port_rules_ != map_.cend()) {
    for (auto& rules : port_rules_->second) {
      // Skip if allowed
      if (allow && rules.can_short_circuit_)
        continue;
      if (allowed(rules, denied))
        allow = true;
    }
  }
  // Wildcard port can deny a specific remote, so need to check for it too.
  for (auto& rules : wildcard_rules_) {
    // Skip if allowed
    if (allow && rules.can_short_circuit_)
      continue;
    if (allowed(rules, denied))
      allow = true;
  }
  return allow && !denied;
}

// for_first_range is used for proxylib parser and TLS context selection.
//
// rules for the specific ports are checked first, and within there singe-port ranges are placed in
// the front, while actual ranges are placed in the back. This results in the following precedence
// order for both proxylib parser and TLS context selection:
//
// 1. single port rules (e.g., port 80)
// 2. port ranges (e.g., ports 80-90)
// 3. Wildcard port rules
//
bool PortPolicy::for_first_range(std::function<bool(const PortNetworkPolicyRules&)> f) const {
  if (port_rules_ != map_.cend()) {
    for (auto& rules : port_rules_->second) {
      if (f(rules))
        return true;
    }
  }
  // Check the wildcard port entry
  for (auto& rules : wildcard_rules_) {
    if (f(rules))
      return true;
  }
  return false;
}

bool PortPolicy::useProxylib(uint32_t remote_id, std::string& l7_proto) const {
  return for_first_range([&](const PortNetworkPolicyRules& rules) -> bool {
    return rules.useProxylib(remote_id, l7_proto);
  });
}

bool PortPolicy::allowed(uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry) const {
  return for_range([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(remote_id, headers, log_entry, denied);
  });
}

bool PortPolicy::allowed(uint32_t remote_id, absl::string_view sni) const {
  return for_range([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(remote_id, sni, denied);
  });
}

bool PortPolicy::allowed(uint32_t remote_id,
                         const envoy::config::core::v3::Metadata& metadata) const {
  return for_range([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(remote_id, metadata, denied);
  });
}

Ssl::ContextSharedPtr PortPolicy::getServerTlsContext(uint32_t remote_id,
                                                      const Ssl::ContextConfig** config) const {
  Ssl::ContextSharedPtr ret;
  for_first_range([&](const PortNetworkPolicyRules& rules) -> bool {
    ret = rules.getServerTlsContext(remote_id, config);
    return ret != nullptr;
  });
  return ret;
}

Ssl::ContextSharedPtr PortPolicy::getClientTlsContext(uint32_t remote_id,
                                                      const Ssl::ContextConfig** config) const {
  Ssl::ContextSharedPtr ret;
  for_first_range([&](const PortNetworkPolicyRules& rules) -> bool {
    ret = rules.getClientTlsContext(remote_id, config);
    return ret != nullptr;
  });
  return ret;
}

// Ranges overlap when one is not completely below or above the other
bool inline ranges_overlap(const PortRange& a, const PortRange& b) {
  // !(a.second < b.first || a.first > b.second)
  return a.second >= b.first && a.first <= b.second;
}

class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicy(const NetworkPolicyMap& parent,
                    const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
    for (const auto& rule : rules) {
      // Only TCP supported for HTTP
      if (rule.protocol() == envoy::config::core::v3::SocketAddress::TCP) {
        // Port may be zero, which matches any port.
        uint16_t port = rule.port();
        // End port may be zero, which means no range
        uint16_t end_port = rule.end_port();
        if (end_port < port) {
          if (end_port != 0) {
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
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP wildcard policy");
          wildcard_rules_.emplace_back(parent, rule.rules());
          continue;
        }
        ENVOY_LOG(trace,
                  "Cilium L7 PortNetworkPolicy(): installing TCP policy for "
                  "port range {}-{}",
                  port, end_port);
        auto rule_range = std::make_pair(port, end_port);
        auto pair = rules_.emplace(rule_range, RulesList{});
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
            if (!ranges_overlap(it->first, rule_range))
              break;
          }
          it = last_overlap; // Move back up to the frontmost overlapping entry

          // absl::btree_map manipulation operations invalidate iterators, so we keep the range
          // (the map key) of the first overlapping entry in 'start_range' to be able to locate
          // the first range that needs the new rules after all the overlaps have been resolved.
          // 'start_key' is updated as needed below.
          auto start_range = it->first;

          // split the current entry due to partial overlap in the beginning?
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
          for (; it != rules_.end() && port <= end_port && end_port >= it->first.first; it++) {
            auto range = it->first;
            // create a new entry below the current one?
            if (port < range.first) {
              auto new_range = std::make_pair(port, std::min(end_port, uint16_t(range.first - 1)));
              auto new_pair = rules_.emplace(new_range, RulesList{});
              RELEASE_ASSERT(new_pair.second,
                             "duplicate entry when explicitly adding a new range!");
              // update the start range if a new start entry was added, which can happen only at the
              // beginning of this loop when port is still at the beginning of the rule range being
              // added.
              if (port == rule_range.first)
                start_range = new_range;
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
            // split the current range into two due to partial overlap in the end?
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
              // current entry completely covered by the new range, skip to the next
              port = range.second + 1;
            }
          }
          // create a new entry covering the end?
          if (port <= end_port) {
            auto new_range = std::make_pair(port, end_port);
            auto new_pair = rules_.emplace(new_range, RulesList{});
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
        auto rules = PortNetworkPolicyRules(parent, rule.rules());
        for (; it != rules_.end() && ranges_overlap(it->first, rule_range); it++) {
          auto range = it->first;
          auto& list = it->second;
          ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): Adding rules for [{}-{}] to [{}-{}]",
                    rule_range.first, rule_range.second, range.first, range.second);
          if (singular) {
            // Exact port rules go to the front of the list.
            // This gives precedence for trivial range rules for proxylib parser
            // and TLS context selection.
            list.push_front(rules);
          } else {
            // Rules with a non-trivial range go to the back of the list
            list.push_back(rules);
          }
        }
      } else {
        ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
      }
    }
  }

  const PortPolicy findPortPolicy(uint16_t port) const {
    return PortPolicy(rules_, wildcard_rules_, port);
  }

  void toString(int indent, std::string& res) const {
    if (rules_.size() == 0) {
      res.append(indent, ' ').append("rules: []\n");
    } else {
      res.append(indent, ' ').append("rules:\n");
      for (auto entry : rules_) {
        res.append(indent + 2, ' ')
            .append(fmt::format("[{}-{}]:\n", entry.first.first, entry.first.second));
        for (auto rule : entry.second) {
          rule.toString(indent + 4, res);
        }
      }
    }
    if (wildcard_rules_.size() == 0) {
      res.append(indent, ' ').append("wildcard_rules: []\n");
    } else {
      res.append(indent, ' ').append("wildcard_rules:\n");
      for (auto rule : wildcard_rules_) {
        rule.toString(indent + 2, res);
      }
    }
  }

  PolicyMap rules_;
  RulesList wildcard_rules_{};
};

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

  bool allowed(bool ingress, uint32_t remote_id, uint16_t port,
               Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.allowed(remote_id, headers, log_entry);
  }

  bool allowed(bool ingress, uint32_t remote_id, absl::string_view sni,
               uint16_t port) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.allowed(remote_id, sni);
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t port) const override {
    return ingress ? ingress_.findPortPolicy(port) : egress_.findPortPolicy(port);
  }

  bool useProxylib(bool ingress, uint32_t remote_id, uint16_t port,
                   std::string& l7_proto) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.useProxylib(remote_id, l7_proto);
  }

  const std::string& conntrackName() const override { return conntrack_map_name_; }

  uint32_t getEndpointID() const override { return endpoint_id_; }

  const IPAddressPair& getEndpointIPs() const override { return endpoint_ips_; }

  std::string String() const override {
    std::string res;
    res.append("ingress:\n");
    ingress_.toString(2, res);
    res.append("egress:\n");
    egress_.toString(2, res);
    return res;
  }

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
    : context_(context.serverFactoryContext()), tls_map_(context_.threadLocal()),
      local_ip_str_(context_.localInfo().address()->ip()->addressAsString()),
      name_(fmt::format("cilium.policymap.{}.{}.", local_ip_str_, ++instance_id_)),
      scope_(context_.serverScope().createScope(name_)),
      init_target_(fmt::format("Cilium Network Policy subscription start"),
                   [this]() { subscription_->start({}); }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context_, context.getTransportSocketFactoryContext().sslContextManager(), *scope_,
              context_.clusterManager(),
              context_.messageValidationContext().dynamicValidationVisitor())) {
  // Use listener init manager for the first initialization
  transport_factory_context_->setInitManager(context.initManager());
  context.initManager().add(init_target_);

  ENVOY_LOG(trace, "NetworkPolicyMap({}) created.", name_);
  tls_map_.set([&](Event::Dispatcher&) { return std::make_shared<ThreadLocalPolicyMap>(); });

  if (context_.admin().has_value()) {
    ENVOY_LOG(debug, "Registering NetworkPolicies to config tracker");
    config_tracker_entry_ = context_.admin()->getConfigTracker().add(
        "networkpolicies", [this](const Matchers::StringMatcher& name_matcher) {
          return dumpNetworkPolicyConfigs(name_matcher);
        });
    RELEASE_ASSERT(config_tracker_entry_, "");
  }
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
void NetworkPolicyMap::startSubscription() {
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicy", context_.localInfo(),
                            context_.clusterManager(), context_.mainThreadDispatcher(),
                            context_.api().randomGenerator(), *scope_, *this,
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

bool NetworkPolicyMap::isNewStream() {
  auto sub = dynamic_cast<Config::GrpcSubscriptionImpl*>(subscription_.get());
  if (!sub) {
    ENVOY_LOG(error, "Cilium NetworkPolicyMap: Cannot get GrpcSubscriptionImpl");
    return false;
  }
  auto mux = dynamic_cast<GrpcMuxImpl*>(sub->grpcMux().get());
  if (!mux) {
    ENVOY_LOG(error, "Cilium NetworkPolicyMap: Cannot get GrpcMuxImpl");
    return false;
  }
  return mux->isNewStream();
}

void ThreadLocalPolicyMap::Update(std::vector<std::shared_ptr<PolicyInstanceImpl>>& added,
                                  std::vector<std::string>& deleted,
                                  const std::string& version_info) {
  ENVOY_LOG(trace,
            "Cilium L7 NetworkPolicyMap::onConfigUpdate(): Starting "
            "updates on the {} thread for version {}",
            Thread::MainThread::isMainThread() ? "main" : "worker", version_info);
  for (const auto& policy_name : deleted) {
    ENVOY_LOG(trace, "Cilium deleting removed network policy for endpoint {}", policy_name);
    policies_.erase(policy_name);
  }
  for (const auto& new_policy : added) {
    for (const auto& endpoint_ip : new_policy->policy_proto_.endpoint_ips()) {
      ENVOY_LOG(trace, "Cilium updating network policy for endpoint {}", endpoint_ip);
      policies_[endpoint_ip] = new_policy;
    }
  }
}

absl::Status
NetworkPolicyMap::onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
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

  // Reopen IPcache for every new stream. Cilium agent re-creates IP cache on restart,
  // and that is also when the old stream terminates and a new one is created.
  // New security identities (e.g., for FQDN policies) only get inserted to the new IP cache,
  // so open it before the workers get a chance to enforce policy on the new IDs.
  if (isNewStream()) {
    // Get ipcache singleton only if it was successfully created previously
    IPCacheSharedPtr ipcache = IPCache::GetIPCache(context_);
    if (ipcache != nullptr) {
      ENVOY_LOG(trace, "Reopening ipcache on new stream");
      ipcache->Open();
    }
  }

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
        ENVOY_LOG(debug, "NetworkPolicyMap expired on watcher completion!");
      }
    });

    // Execute changes on all threads.
    tls_map_.runOnAllThreads(
        [to_be_added, to_be_deleted, version_info](OptRef<ThreadLocalPolicyMap> npmap) {
          // Main thread done after the worker threads
          if (Thread::MainThread::isMainThread())
            return;

          if (!npmap.has_value()) {
            ENVOY_LOG(debug,
                      "Cilium L7 NetworkPolicyMap::onConfigUpdate(): npmap has no value "
                      "for version {}",
                      version_info);
            return;
          }
          npmap->Update(*to_be_added, *to_be_deleted, version_info);
        },
        // All threads have executed updates, delete old cts and mark the local init target ready.
        [shared_this, to_be_added, to_be_deleted, version_info, cts_to_be_closed]() {
          // Update on the main thread last, so that deletes happen on the same thread as allocs
          auto npmap = shared_this->tls_map_.get();
          npmap->Update(*to_be_added, *to_be_deleted, version_info);

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
  return absl::OkStatus();
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

ProtobufTypes::MessagePtr
NetworkPolicyMap::dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher) {
  ENVOY_LOG(debug, "Writing NetworkPolicies to NetworkPoliciesConfigDump");

  std::vector<uint64_t> policyEndpointIds;
  auto config_dump = std::make_unique<cilium::NetworkPoliciesConfigDump>();
  for (const auto& item : tls_map_->policies_) {
    // filter duplicates (policies are stored per endpoint ip)
    if (std::find(policyEndpointIds.begin(), policyEndpointIds.end(),
                  item.second->policy_proto_.endpoint_id()) != policyEndpointIds.end()) {
      continue;
    }

    if (!name_matcher.match(item.first)) {
      continue;
    }

    config_dump->mutable_networkpolicies()->Add()->CopyFrom(item.second->policy_proto_);
    policyEndpointIds.emplace_back(item.second->policy_proto_.endpoint_id());
  }

  return config_dump;
}

// Allow-all Egress policy
class AllowAllEgressPolicyInstanceImpl : public PolicyInstance {
public:
  AllowAllEgressPolicyInstanceImpl() {
    auto& list =
        empty_map_.emplace(std::make_pair(uint16_t(1), uint16_t(1)), RulesList{}).first->second;
    list.emplace_front(PortNetworkPolicyRules());
  }

  bool allowed(bool ingress, uint32_t, uint16_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return ingress ? false : true;
  }

  bool allowed(bool ingress, uint32_t, absl::string_view, uint16_t) const override {
    return ingress ? false : true;
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t) const override {
    return ingress ? PortPolicy(empty_map_, empty_rules_, 0)
                   : PortPolicy(empty_map_, empty_rules_, 1);
  }

  bool useProxylib(bool, uint32_t, uint16_t, std::string&) const override { return false; }

  const std::string& conntrackName() const override { return empty_string; }

  uint32_t getEndpointID() const override { return 0; }

  const IPAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string String() const override { return "AllowAllEgressPolicyInstanceImpl"; }

private:
  PolicyMap empty_map_;
  static const std::string empty_string;
  static const IPAddressPair empty_ips;
  static const RulesList empty_rules_;
};
const std::string AllowAllEgressPolicyInstanceImpl::empty_string = "";
const IPAddressPair AllowAllEgressPolicyInstanceImpl::empty_ips{};
const RulesList AllowAllEgressPolicyInstanceImpl::empty_rules_{};

PolicyInstanceConstSharedPtr NetworkPolicyMap::AllowAllEgressPolicy =
    std::make_shared<AllowAllEgressPolicyInstanceImpl>();

} // namespace Cilium
} // namespace Envoy
