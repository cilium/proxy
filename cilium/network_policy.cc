#include "cilium/network_policy.h"

#include <fmt/format.h>
#include <openssl/mem.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/common/matchers.h"
#include "envoy/common/optref.h"
#include "envoy/config/core/v3/address.pb.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/http/header_map.h"
#include "envoy/init/manager.h"
#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/type/matcher/v3/metadata.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/logger.h"
#include "source/common/common/matchers.h"
#include "source/common/common/thread.h"
#include "source/common/http/header_utility.h"
#include "source/common/init/manager_impl.h"
#include "source/common/init/target_impl.h"
#include "source/common/init/watcher_impl.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"
#include "source/extensions/config_subscription/grpc/grpc_subscription_impl.h"
#include "source/server/transport_socket_config_impl.h"

#include "absl/container/btree_set.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/conntrack.h"
#include "cilium/grpc_subscription.h"
#include "cilium/ipcache.h"
#include "cilium/secret_watcher.h"

namespace Envoy {
namespace Cilium {

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
    if (config.value_sds_secret().length() > 0) {
      secret_ = std::make_unique<SecretWatcher>(parent, config.value_sds_secret());
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
      } else if (value_.length() == 0) {
        // fail if secret has no value and the inline value to match is also empty
        ENVOY_LOG(info, "Cilium HeaderMatch missing SDS secret value for header {}", name_);
        return false;
      }
    }

    // Perform presence match if the value to match is empty
    bool is_present_match = match_value->length() == 0;
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

        // Remove the header with an incorrect value
        headers.remove(name_);
        logRejected(log_entry, header_value.result().value());
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
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataRegexMatch*>(h.get())) {
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
        } else if (const auto v =
                       dynamic_cast<Http::HeaderUtility::HeaderDataStringMatch*>(h.get())) {
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

class L7NetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
public:
  L7NetworkPolicyRule(const NetworkPolicyMapImpl& parent, const cilium::L7NetworkPolicyRule& rule)
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
  PortNetworkPolicyRule(const NetworkPolicyMapImpl& parent,
                        const cilium::PortNetworkPolicyRule& rule)
      : name_(rule.name()), deny_(rule.deny()), proxy_id_(rule.proxy_id()),
        l7_proto_(rule.l7_proto()) {
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
      allowed_snis_.emplace_back(sni);
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

  bool allowed(uint32_t proxy_id, uint32_t remote_id, bool& denied) const {
    // proxy_id must match if we have any.
    if (proxy_id_ != 0 && proxy_id != proxy_id_) {
      return false;
    }
    // Remote ID must match if we have any.
    if (!remotes_.empty()) {
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

  bool allowed(uint32_t proxy_id, uint32_t remote_id, absl::string_view sni, bool& denied) const {
    // sni must match if we have any
    if (!allowed_snis_.empty()) {
      if (sni.length() == 0) {
        return false;
      }
      bool matched = false;
      for (const auto& pattern : allowed_snis_) {
        if (pattern.matches(sni)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        return false;
      }
    }
    return allowed(proxy_id, remote_id, denied);
  }

  bool allowed(uint32_t proxy_id, uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry, bool& denied) const {
    if (!allowed(proxy_id, remote_id, denied)) {
      return false;
    }
    if (!http_rules_.empty()) {
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
          if (rule.headerMatches(headers, log_entry)) {
            allowed = true;
          }
        }
      }
      return allowed;
    }
    // Empty set matches any payload
    return true;
  }

  bool useProxylib(uint32_t proxy_id, uint32_t remote_id, std::string& l7_proto) const {
    bool denied = false;
    if (!allowed(proxy_id, remote_id, denied)) {
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
  bool allowed(uint32_t proxy_id, uint32_t remote_id,
               const envoy::config::core::v3::Metadata& metadata, bool& denied) const {
    if (!allowed(proxy_id, remote_id, denied)) {
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
    if (!l7_allow_rules_.empty()) {
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

  Ssl::ContextSharedPtr getServerTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const {
    bool denied = false;
    if (allowed(proxy_id, remote_id, sni, denied)) {
      if (server_context_) {
        *config = &server_context_->getTlsContextConfig();
        return server_context_->getTlsContext();
      }
      raw_socket_allowed = true;
    }
    return nullptr;
  }

  Ssl::ContextSharedPtr getClientTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const {
    bool denied = false;
    if (allowed(proxy_id, remote_id, sni, denied)) {
      if (client_context_) {
        *config = &client_context_->getTlsContextConfig();
        return client_context_->getTlsContext();
      }
      raw_socket_allowed = true;
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
    if (proxy_id_ != 0) {
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

    if (!http_rules_.empty()) {
      res.append(indent, ' ').append("http_rules:\n");
      for (auto& rule : http_rules_) {
        rule.toString(indent + 2, res);
      }
    }

    if (!l7_proto_.empty()) {
      res.append(indent, ' ').append("l7_proto: \"").append(l7_proto_).append("\"\n");
    }
    if (!l7_allow_rules_.empty()) {
      res.append(indent, ' ').append("l7_allow_rules:\n");
      for (auto& rule : l7_allow_rules_) {
        rule.toString(indent + 2, res);
      }
    }
    if (!l7_deny_rules_.empty()) {
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
  uint32_t proxy_id_;
  absl::btree_set<uint32_t> remotes_;

  std::vector<SniPattern> allowed_snis_;          // All SNIs allowed if empty.
  std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
  std::string l7_proto_{};
  std::vector<L7NetworkPolicyRule> l7_allow_rules_;
  std::vector<L7NetworkPolicyRule> l7_deny_rules_;
};
using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicyRules() = default;
  PortNetworkPolicyRules(const NetworkPolicyMapImpl& parent,
                         const Protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
    if (rules.empty()) {
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

  ~PortNetworkPolicyRules() {
    if (!Thread::MainThread::isMainOrTestThread()) {
      IS_ENVOY_BUG("PortNetworkPolicyRules: Destructor executing in a worker thread, while "
                   "only main thread should destruct xDS resources");
    }
  }

  bool allowed(uint32_t proxy_id, uint32_t remote_id, Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry, bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.empty()) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(proxy_id, remote_id, headers, log_entry, denied)) {
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

  bool allowed(uint32_t proxy_id, uint32_t remote_id, absl::string_view sni, bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.empty()) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(proxy_id, remote_id, sni, denied)) {
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

  bool useProxylib(uint32_t proxy_id, uint32_t remote_id, std::string& l7_proto) const {
    for (const auto& rule : rules_) {
      if (rule->useProxylib(proxy_id, remote_id, l7_proto)) {
        return true;
      }
    }
    return false;
  }

  bool allowed(uint32_t proxy_id, uint32_t remote_id,
               const envoy::config::core::v3::Metadata& metadata, bool& denied) const {
    // Empty set matches any payload from anyone
    if (rules_.empty()) {
      return true;
    }

    bool allowed = false;
    for (const auto& rule : rules_) {
      if (rule->allowed(proxy_id, remote_id, metadata, denied)) {
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

  Ssl::ContextSharedPtr getServerTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const {
    for (const auto& rule : rules_) {
      Ssl::ContextSharedPtr server_context =
          rule->getServerTlsContext(proxy_id, remote_id, sni, config, raw_socket_allowed);
      if (server_context) {
        return server_context;
      }
    }
    return nullptr;
  }

  Ssl::ContextSharedPtr getClientTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                            absl::string_view sni,
                                            const Ssl::ContextConfig** config,
                                            bool& raw_socket_allowed) const {
    for (const auto& rule : rules_) {
      Ssl::ContextSharedPtr client_context =
          rule->getClientTlsContext(proxy_id, remote_id, sni, config, raw_socket_allowed);
      if (client_context) {
        return client_context;
      }
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

// forRange is used for policy lookups, so it will need to check both port-specific and
// wildcard-port rules, as either of them could contain rules that must be evaluated (i.e., deny
// or header match rules with side effects).
bool PortPolicy::forRange(
    std::function<bool(const PortNetworkPolicyRules&, bool& denied)> allowed) const {
  bool allow = false;
  bool denied = false;
  if (port_rules_ != map_.cend()) {
    for (auto& rules : port_rules_->second) {
      // Skip if allowed
      if (allow && rules.can_short_circuit_) {
        continue;
      }
      if (allowed(rules, denied)) {
        allow = true;
      }
    }
  }
  // Wildcard port can deny a specific remote, so need to check for it too.
  for (auto& rules : wildcard_rules_) {
    // Skip if allowed
    if (allow && rules.can_short_circuit_) {
      continue;
    }
    if (allowed(rules, denied)) {
      allow = true;
    }
  }
  return allow && !denied;
}

// forFirstRange is used for proxylib parser and TLS context selection.
//
// rules for the specific ports are checked first, and within there singe-port ranges are placed in
// the front, while actual ranges are placed in the back. This results in the following precedence
// order for both proxylib parser and TLS context selection:
//
// 1. single port rules (e.g., port 80)
// 2. port ranges (e.g., ports 80-90)
// 3. Wildcard port rules
//
bool PortPolicy::forFirstRange(std::function<bool(const PortNetworkPolicyRules&)> f) const {
  if (port_rules_ != map_.cend()) {
    for (auto& rules : port_rules_->second) {
      if (f(rules)) {
        return true;
      }
    }
  }
  // Check the wildcard port entry
  for (auto& rules : wildcard_rules_) {
    if (f(rules)) {
      return true;
    }
  }
  return false;
}

bool PortPolicy::useProxylib(uint32_t proxy_id, uint32_t remote_id, std::string& l7_proto) const {
  return forFirstRange([&](const PortNetworkPolicyRules& rules) -> bool {
    return rules.useProxylib(proxy_id, remote_id, l7_proto);
  });
}

bool PortPolicy::allowed(uint32_t proxy_id, uint32_t remote_id,
                         Envoy::Http::RequestHeaderMap& headers,
                         Cilium::AccessLog::Entry& log_entry) const {
  return forRange([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(proxy_id, remote_id, headers, log_entry, denied);
  });
}

bool PortPolicy::allowed(uint32_t proxy_id, uint32_t remote_id, absl::string_view sni) const {
  return forRange([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(proxy_id, remote_id, sni, denied);
  });
}

bool PortPolicy::allowed(uint32_t proxy_id, uint32_t remote_id,
                         const envoy::config::core::v3::Metadata& metadata) const {
  return forRange([&](const PortNetworkPolicyRules& rules, bool& denied) -> bool {
    return rules.allowed(proxy_id, remote_id, metadata, denied);
  });
}

Ssl::ContextSharedPtr PortPolicy::getServerTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig** config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr ret;
  forFirstRange([&](const PortNetworkPolicyRules& rules) -> bool {
    ret = rules.getServerTlsContext(proxy_id, remote_id, sni, config, raw_socket_allowed);
    return ret != nullptr;
  });
  return ret;
}

Ssl::ContextSharedPtr PortPolicy::getClientTlsContext(uint32_t proxy_id, uint32_t remote_id,
                                                      absl::string_view sni,
                                                      const Ssl::ContextConfig** config,
                                                      bool& raw_socket_allowed) const {
  Ssl::ContextSharedPtr ret;
  forFirstRange([&](const PortNetworkPolicyRules& rules) -> bool {
    ret = rules.getClientTlsContext(proxy_id, remote_id, sni, config, raw_socket_allowed);
    return ret != nullptr;
  });
  return ret;
}

// Ranges overlap when one is not completely below or above the other
bool inline rangesOverlap(const PortRange& a, const PortRange& b) {
  // !(a.second < b.first || a.first > b.second)
  return a.second >= b.first && a.first <= b.second;
}

class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
public:
  PortNetworkPolicy(const NetworkPolicyMapImpl& parent,
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
        for (; it != rules_.end() && rangesOverlap(it->first, rule_range); it++) {
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
    if (rules_.empty()) {
      res.append(indent, ' ').append("rules: []\n");
    } else {
      res.append(indent, ' ').append("rules:\n");
      for (const auto& entry : rules_) {
        res.append(indent + 2, ' ')
            .append(fmt::format("[{}-{}]:\n", entry.first.first, entry.first.second));
        for (const auto& rule : entry.second) {
          rule.toString(indent + 4, res);
        }
      }
    }
    if (wildcard_rules_.empty()) {
      res.append(indent, ' ').append("wildcard_rules: []\n");
    } else {
      res.append(indent, ' ').append("wildcard_rules:\n");
      for (const auto& rule : wildcard_rules_) {
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
  PolicyInstanceImpl(const NetworkPolicyMapImpl& parent, uint64_t hash,
                     const cilium::NetworkPolicy& proto)
      : conntrack_map_name_(proto.conntrack_map_name()), endpoint_id_(proto.endpoint_id()),
        hash_(hash), policy_proto_(proto), endpoint_ips_(proto), parent_(parent),
        ingress_(parent, policy_proto_.ingress_per_port_policies()),
        egress_(parent, policy_proto_.egress_per_port_policies()) {}

  bool allowed(bool ingress, uint32_t proxy_id, uint32_t remote_id, uint16_t port,
               Envoy::Http::RequestHeaderMap& headers,
               Cilium::AccessLog::Entry& log_entry) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.allowed(proxy_id, remote_id, headers, log_entry);
  }

  bool allowed(bool ingress, uint32_t proxy_id, uint32_t remote_id, absl::string_view sni,
               uint16_t port) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.allowed(proxy_id, remote_id, sni);
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t port) const override {
    return ingress ? ingress_.findPortPolicy(port) : egress_.findPortPolicy(port);
  }

  bool useProxylib(bool ingress, uint32_t proxy_id, uint32_t remote_id, uint16_t port,
                   std::string& l7_proto) const override {
    const auto port_policy = findPortPolicy(ingress, port);
    return port_policy.useProxylib(proxy_id, remote_id, l7_proto);
  }

  const std::string& conntrackName() const override { return conntrack_map_name_; }

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
  std::string conntrack_map_name_;
  uint32_t endpoint_id_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;
  const IpAddressPair endpoint_ips_;

private:
  const NetworkPolicyMapImpl& parent_;
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

// Common base constructor
// This is used directly for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context)
    : context_(context.serverFactoryContext()) {
  impl_ = std::make_unique<NetworkPolicyMapImpl>(context);

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
  getImpl().setConntrackMap(ct);
  getImpl().startSubscription();
}

NetworkPolicyMap::~NetworkPolicyMap() {
  ENVOY_LOG(debug,
            "Cilium L7 NetworkPolicyMap: posting NetworkPolicyMapImpl deletion to main thread");

  // Policy map destruction happens when the last listener with the Cilium bpf_metadata listener
  // filter has drained out and is finally removed, and last connection of the old listener is
  // closed. This does not happen if new listener(s) with references to policy map are created in
  // the meanwhile.
  //
  // Destruction of the NetworkPolicyMapImpl must be made from the main thread to ensure integrity
  // of SDS subscription management. Since this can be called from a worker thread of the last
  // connection we must post the destruction to the main thread dispatcher.
  //
  // Move the NetworkPolicyMapImpl to the lambda capture so that it goes out of scope and gets
  // deleted in the main thread.

  context_.mainThreadDispatcher().post([impl = std::move(impl_)]() {});
}

NetworkPolicyMapImpl::NetworkPolicyMapImpl(Server::Configuration::FactoryContext& context)
    : context_(context.serverFactoryContext()), map_ptr_(nullptr),
      npds_stats_scope_(context_.serverScope().createScope("cilium.npds.")),
      policy_stats_scope_(context_.serverScope().createScope("cilium.policy.")),
      init_target_(fmt::format("Cilium Network Policy subscription start"),
                   [this]() {
                     subscription_->start({});
                     // Allow listener init to continue before network policy updates are received
                     init_target_.ready();
                   }),
      transport_factory_context_(
          std::make_shared<Server::Configuration::TransportSocketFactoryContextImpl>(
              context_, context.getTransportSocketFactoryContext().sslContextManager(),
              *npds_stats_scope_, context_.clusterManager(),
              context_.messageValidationContext().dynamicValidationVisitor())),
      stats_{ALL_CILIUM_POLICY_STATS(POOL_COUNTER(*policy_stats_scope_),
                                     POOL_HISTOGRAM(*policy_stats_scope_))} {
  // Use listener init manager for subscription initialization
  context.initManager().add(init_target_);

  // Allocate an initial policy map so that the map pointer is never a nullptr
  store(new RawPolicyMap());
  ENVOY_LOG(trace, "NetworkPolicyMapImpl({}) created.", instance_id_);
}

// NetworkPolicyMapImpl destructor must only be called from the main thread.
NetworkPolicyMapImpl::~NetworkPolicyMapImpl() {
  ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMapImpl({}): NetworkPolicyMap is deleted NOW!",
            instance_id_);
  delete load();
}

void NetworkPolicyMapImpl::startSubscription() {
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicy", context_.localInfo(),
                            context_.clusterManager(), context_.mainThreadDispatcher(),
                            context_.api().randomGenerator(), *npds_stats_scope_, *this,
                            std::make_shared<NetworkPolicyDecoder>());
}

void NetworkPolicyMapImpl::tlsWrapperMissingPolicyInc() const {
  stats_.tls_wrapper_missing_policy_.inc();
}

bool NetworkPolicyMapImpl::isNewStream() {
  auto sub = dynamic_cast<Config::GrpcSubscriptionImpl*>(subscription_.get());
  if (!sub) {
    ENVOY_LOG(error, "Cilium NetworkPolicyMapImpl: Cannot get GrpcSubscriptionImpl");
    return false;
  }
  auto mux = dynamic_cast<GrpcMuxImpl*>(sub->grpcMux().get());
  if (!mux) {
    ENVOY_LOG(error, "Cilium NetworkPolicyMapImpl: Cannot get GrpcMuxImpl");
    return false;
  }
  return mux->isNewStream();
}

// removeInitManager must be called at the end of each policy update
void NetworkPolicyMapImpl::removeInitManager() {
  // Remove the local init manager from the transport factory context
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnull-dereference"
#endif
  transport_factory_context_->setInitManager(*static_cast<Init::Manager*>(nullptr));
#ifdef __clang__
#pragma clang diagnostic pop
#endif
}

// onConfigUpdate parses the new network policy resources, allocates a new policy map and atomically
// swaps it in place of the old policy map. Throws if any of the 'resources' can not be
// parsed. Otherwise an OK status is returned without pausing NPDS gRPC stream, causing a new
// request (ACK) to be sent immediately, without waiting SDS secrets to be loaded.
absl::Status NetworkPolicyMapImpl::onConfigUpdate(
    const std::vector<Envoy::Config::DecodedResourceRef>& resources,
    const std::string& version_info) {
  ENVOY_LOG(debug, "NetworkPolicyMapImpl::onConfigUpdate({}), {} resources, version: {}",
            instance_id_, resources.size(), version_info);
  stats_.updates_total_.inc();

  // Reopen IPcache for every new stream. Cilium agent re-creates IP cache on restart,
  // and that is also when the old stream terminates and a new one is created.
  // New security identities (e.g., for FQDN policies) only get inserted to the new IP cache,
  // so open it before the workers get a chance to enforce policy on the new IDs.
  if (isNewStream()) {
    ENVOY_LOG(info, "New NetworkPolicy stream");

    // Get ipcache singleton only if it was successfully created previously
    IpCacheSharedPtr ipcache = IpCache::getIpCache(context_);
    if (ipcache != nullptr) {
      ENVOY_LOG(info, "Reopening ipcache on new stream");
      ipcache->open();
    }
  }

  std::string version_name = fmt::format("NetworkPolicyMap version {}", version_info);
  Init::ManagerImpl version_init_manager(version_name);
  // Set the init manager to use via the transport factory context
  // Must be set before the new network policy is parsed, as the parsed
  // SDS secrets will use this!
  transport_factory_context_->setInitManager(version_init_manager);

  absl::flat_hash_set<std::string> ctmaps_to_be_closed;

  const auto* old_map = load();
  {
    absl::flat_hash_set<std::string> ctmaps_to_keep;
    auto new_map = new RawPolicyMap();
    try {
      for (const auto& resource : resources) {
        const auto& config = dynamic_cast<const cilium::NetworkPolicy&>(resource.get().resource());
        ENVOY_LOG(debug,
                  "Received Network Policy for endpoint {}, endpoint_ip {} in onConfigUpdate() "
                  "version {}",
                  config.endpoint_id(), config.endpoint_ips()[0], version_info);
        if (config.endpoint_ips().empty()) {
          throw EnvoyException("Network Policy has no endpoint ips");
        }
        ctmaps_to_keep.insert(config.conntrack_map_name());

        // First find the old config to figure out if an update is needed.
        const uint64_t new_hash = MessageUtil::hash(config);
        auto it = old_map->find(config.endpoint_ips()[0]);
        if (it != old_map->cend()) {
          const auto& old_policy = it->second;
          if (old_policy && old_policy->hash_ == new_hash &&
              Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
            ENVOY_LOG(trace, "New policy is equal to old one, not updating.");
            for (const auto& endpoint_ip : config.endpoint_ips()) {
              ENVOY_LOG(trace, "Cilium keeping network policy for endpoint {}", endpoint_ip);
              new_map->emplace(endpoint_ip, old_policy);
            }
            continue;
          }
        }

        // May throw
        auto new_policy = std::make_shared<const PolicyInstanceImpl>(*this, new_hash, config);

        for (const auto& endpoint_ip : config.endpoint_ips()) {
          ENVOY_LOG(trace, "Cilium updating network policy for endpoint {}", endpoint_ip);
          // new_map is not exception safe, new_policy must be computed separately!
          new_map->emplace(endpoint_ip, new_policy);
        }
      }
    } catch (const EnvoyException& e) {
      ENVOY_LOG(warn, "NetworkPolicy update for version {} failed: {}", version_info, e.what());
      stats_.updates_rejected_.inc();

      removeInitManager();
      throw; // re-throw
    }
    removeInitManager();

    // Initialize SDS secrets. We do not wait for the completion.
    version_init_manager.initialize(Init::WatcherImpl(version_name, []() {}));

    // Add old ctmaps to be closed
    //
    // NOTE: Support for local CT maps was removed in Cilium 1.17. This clean-up code can be
    // simplified by always keeping the global map open when Cilium 1.17 is the oldest supported
    // version.
    for (auto& pair : *old_map) {
      // insert conntrack map names we don't want to keep
      auto& ct_map_name = pair.second->conntrack_map_name_;
      if (ctmaps_to_keep.find(ct_map_name) == ctmaps_to_keep.end()) {
        ctmaps_to_be_closed.insert(ct_map_name);
      }
    }

    // Swap the new map in, new_map goes out of scope right after to eliminate accidental
    // modification.
    old_map = exchange(new_map);
  }

  // Delete the old map once all worker threads have entered their event queues, as this
  // is proof that they no longer refer to the old map.
  runAfterAllThreads([ctmap = ctmap_, ctmaps_to_be_closed, old_map]() {
    // Clean-up in the main thread after all threads have scheduled
    if (ctmap) {
      ctmap->closeMaps(ctmaps_to_be_closed);
    }
    delete old_map;
  });

  return absl::OkStatus();
}

void NetworkPolicyMapImpl::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                                                const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(debug, "Network Policy Update failed, keeping existing policy.");
}

void NetworkPolicyMapImpl::runAfterAllThreads(std::function<void()> cb) const {
  // We can guarantee the callback 'cb' runs in the main thread after all worker threads have
  // entered their event loop, and thus relinquished all state, such as policy lookup results that
  // were stored in their call stack, by posting and empty function to their event queues and
  // waiting until all of them have returned, as managed by 'runOnAllWorkerThreads'.
  //
  // For now we rely on the implementation dependent fact that the reference returned by
  // context_.threadLocal() actually is a ThreadLocal::Instance reference, where
  // runOnAllWorkerThreads() is exposed. Without this cast we'd need to use a dummy thread local
  // variable that would take a thread local slot for no other purpose than to avoid this type cast.
  dynamic_cast<ThreadLocal::Instance&>(context_.threadLocal()).runOnAllWorkerThreads([]() {}, cb);
}

ProtobufTypes::MessagePtr
NetworkPolicyMap::dumpNetworkPolicyConfigs(const Matchers::StringMatcher& name_matcher) {
  ENVOY_LOG(debug, "Writing NetworkPolicies to NetworkPoliciesConfigDump");

  std::vector<uint64_t> policy_endpoint_ids;
  auto config_dump = std::make_unique<cilium::NetworkPoliciesConfigDump>();
  for (const auto& item : *getImpl().load()) {
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
class AllowAllEgressPolicyInstanceImpl : public PolicyInstance {
public:
  AllowAllEgressPolicyInstanceImpl() {
    auto& list =
        empty_map_.emplace(std::make_pair(uint16_t(1), uint16_t(1)), RulesList{}).first->second;
    list.emplace_front(PortNetworkPolicyRules());
  }

  bool allowed(bool ingress, uint32_t, uint32_t, uint16_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return ingress ? false : true;
  }

  bool allowed(bool ingress, uint32_t, uint32_t, absl::string_view, uint16_t) const override {
    return ingress ? false : true;
  }

  const PortPolicy findPortPolicy(bool ingress, uint16_t) const override {
    return ingress ? PortPolicy(empty_map_, empty_rules_, 0)
                   : PortPolicy(empty_map_, empty_rules_, 1);
  }

  bool useProxylib(bool, uint32_t, uint32_t, uint16_t, std::string&) const override {
    return false;
  }

  const std::string& conntrackName() const override { return empty_string; }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "AllowAllEgressPolicyInstanceImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicyMap empty_map_;
  static const std::string empty_string;
  static const IpAddressPair empty_ips;
  static const RulesList empty_rules_;
};
const std::string AllowAllEgressPolicyInstanceImpl::empty_string = "";
const IpAddressPair AllowAllEgressPolicyInstanceImpl::empty_ips{};
const RulesList AllowAllEgressPolicyInstanceImpl::empty_rules_{};

AllowAllEgressPolicyInstanceImpl NetworkPolicyMap::AllowAllEgressPolicy;

PolicyInstance& NetworkPolicyMap::getAllowAllEgressPolicy() { return AllowAllEgressPolicy; }

// Deny-all policy
class DenyAllPolicyInstanceImpl : public PolicyInstance {
public:
  DenyAllPolicyInstanceImpl() = default;

  bool allowed(bool, uint32_t, uint32_t, uint16_t, Envoy::Http::RequestHeaderMap&,
               Cilium::AccessLog::Entry&) const override {
    return false;
  }

  bool allowed(bool, uint32_t, uint32_t, absl::string_view, uint16_t) const override {
    return false;
  }

  const PortPolicy findPortPolicy(bool, uint16_t) const override {
    return PortPolicy(empty_map_, empty_rules, 0);
  }

  bool useProxylib(bool, uint32_t, uint32_t, uint16_t, std::string&) const override {
    return false;
  }

  const std::string& conntrackName() const override { return empty_string; }

  uint32_t getEndpointID() const override { return 0; }

  const IpAddressPair& getEndpointIPs() const override { return empty_ips; }

  std::string string() const override { return "DenyAllPolicyInstanceImpl"; }

  void tlsWrapperMissingPolicyInc() const override {}

private:
  PolicyMap empty_map_;
  static const std::string empty_string;
  static const IpAddressPair empty_ips;
  static const RulesList empty_rules;
};
const std::string DenyAllPolicyInstanceImpl::empty_string = "";
const IpAddressPair DenyAllPolicyInstanceImpl::empty_ips{};
const RulesList DenyAllPolicyInstanceImpl::empty_rules{};

DenyAllPolicyInstanceImpl NetworkPolicyMap::DenyAllPolicy;

PolicyInstance& NetworkPolicyMap::getDenyAllPolicy() { return DenyAllPolicy; }

const PolicyInstance*
NetworkPolicyMapImpl::getPolicyInstanceImpl(const std::string& endpoint_ip) const {
  const auto* map = load();
  auto it = map->find(endpoint_ip);
  if (it != map->end()) {
    return it->second.get();
  }
  return nullptr;
}

// getPolicyInstance return a const reference to a policy in the policy map for the given
// 'endpoint_ip'. If there is no policy for the given IP, a default policy is returned,
// controlled by the 'default_allow_egress' argument as follows:
//
// 'false' - a deny all policy is returned,
// 'true' -  a deny all ingress / allow all egress is returned.
//
// Returning a default deny policy makes the caller report a "policy deny" rather than "internal
// server error" if no policy is found. This mirrors what bpf datapath does if no policy entry is
// found in the bpf policy map. The default deny for ingress with default allow for egress is needed
// for Cilium Ingress when there is no egress policy enforcement for the Ingress traffic.
const PolicyInstance& NetworkPolicyMap::getPolicyInstance(const std::string& endpoint_ip,
                                                          bool default_allow_egress) const {
  const auto* policy = getImpl().getPolicyInstanceImpl(endpoint_ip);
  return policy != nullptr      ? *policy
         : default_allow_egress ? *static_cast<PolicyInstance*>(&AllowAllEgressPolicy)
                                : *static_cast<PolicyInstance*>(&DenyAllPolicy);
}

} // namespace Cilium
} // namespace Envoy
