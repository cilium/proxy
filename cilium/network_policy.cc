#include "cilium/network_policy.h"
#include "cilium/api/npds.pb.validate.h"
#include "cilium/grpc_subscription.h"

#include <string>
#include <unordered_set>

#include "common/common/matchers.h"
#include "common/config/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Cilium {

uint64_t NetworkPolicyMap::instance_id_ = 0;

class PolicyInstanceImpl : public PolicyInstance {
public:
  PolicyInstanceImpl(const NetworkPolicyMap& parent, uint64_t hash, const cilium::NetworkPolicy& proto)
    : conntrack_map_name_(proto.conntrack_map_name()), hash_(hash), policy_proto_(proto),
      ingress_(parent, policy_proto_.ingress_per_port_policies()),
      egress_(parent, policy_proto_.egress_per_port_policies()) {}

protected:
  class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    static envoy::config::route::v3::HeaderMatcher matcher(const cilium::HeaderMatch& config) {
      envoy::config::route::v3::HeaderMatcher match;
      match.set_name(config.name());
      if (config.value().length() == 0) {
	match.set_present_match(true);
      } else {
	match.set_exact_match(config.value());
      }
      return match;
    }
    class HeaderMatch : public Envoy::Http::HeaderUtility::HeaderData {
    public:
      HeaderMatch(const cilium::HeaderMatch& config)
	: HeaderData(matcher(config)),
	match_action_(config.match_action()),
	mismatch_action_(config.mismatch_action()) {}

      cilium::HeaderMatch::MatchAction match_action_;
      cilium::HeaderMatch::MismatchAction mismatch_action_;
    };
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
		  ? "<VALUE>"
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Present
		  ? "<PRESENT>"
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Regex
		  ? "<REGEX>" : "<UNKNOWN>");
      }
      for (const auto& config: rule.header_matches()) {
	header_matches_.emplace_back(HeaderMatch(config));
	const auto& header_data = header_matches_.back();
	ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData for headers_action {}={} (match: {}, mismatch: {})",
		  header_data.name_.get(),
		  header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Range
		  ? fmt::format("[{}-{})", header_data.range_.start(), header_data.range_.end())
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Value
		  ? header_data.value_
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Present
		  ? "<PRESENT>"
		  : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Regex
		  ? "<REGEX>" : "<UNKNOWN>",
		  header_data.match_action_, header_data.mismatch_action_);
      }
    }

    bool Matches(const Envoy::Http::RequestHeaderMap& headers) const {
      // Empty set matches any headers.
      return Envoy::Http::HeaderUtility::matchHeaders(headers, headers_);
    }

    // Should only be called after 'Matches' returns 'true'.
    // Returns 'true' if matching can continue
    bool HeaderMatches(Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
      bool accepted = true;
      for (const auto& header_data : header_matches_) {
	::cilium::KeyValue *kv;
	if (Envoy::Http::HeaderUtility::matchHeaders(headers, header_data)) {
	  // Match action
	  switch (header_data.match_action_) {
	  case cilium::HeaderMatch::CONTINUE_ON_MATCH:
	    continue;
	  case cilium::HeaderMatch::FAIL_ON_MATCH:
	  default: // fail closed if unknown action
	    accepted = false;
	    break;
	  case cilium::HeaderMatch::DELETE_ON_MATCH:
	    headers.remove(header_data.name_);
	    break;
	  }
	  kv = log_entry.entry_.mutable_http()->add_rejected_headers();
	} else {
	  // Mismatch action
	  switch (header_data.mismatch_action_) {
	  case cilium::HeaderMatch::FAIL_ON_MISMATCH:
	  default:
	    kv = log_entry.entry_.mutable_http()->add_missing_headers();
	    accepted = false;
	    break;
	  case cilium::HeaderMatch::CONTINUE_ON_MISMATCH:
	    kv = log_entry.entry_.mutable_http()->add_missing_headers();
	    continue;
	  case cilium::HeaderMatch::ADD_ON_MISMATCH:
	    headers.addReferenceKey(header_data.name_, header_data.value_);
	    kv = log_entry.entry_.mutable_http()->add_missing_headers();
	    break;
	  case cilium::HeaderMatch::DELETE_ON_MISMATCH:
	    if (header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Present) {
	      // presence match failed, nothing to do
	      continue;
	    }
	    {
	      // otherwise need to find out if the header existed or not
	      const Envoy::Http::HeaderEntry* entry;
	      auto res = headers.lookup(header_data.name_, &entry);
	      struct Ctx {
		const std::string& name_;
		const Envoy::Http::HeaderString* value_;
	      } ctx = {
		header_data.name_.get(),
		res == Envoy::Http::RequestHeaderMap::Lookup::Found ? &entry->value() : nullptr
	      };
	      if (res == Envoy::Http::RequestHeaderMap::Lookup::NotSupported) {
		// non-supported header, find by iteration
		headers.iterate([](const Envoy::Http::HeaderEntry& entry, void* ctx_) {
				  auto* ctx = static_cast<Ctx*>(ctx_);
				  if (entry.key() == ctx->name_) {
				    ctx->value_ = &entry.value();
				    return Envoy::Http::HeaderMap::Iterate::Break;
				  }
				  return Envoy::Http::HeaderMap::Iterate::Continue;
				}, &ctx);
	      }
	      if (!ctx.value_) {
		continue; // nothing to remove
	      }
	      // Remove the header with an incorrect value
	      headers.remove(header_data.name_);
	      kv = log_entry.entry_.mutable_http()->add_rejected_headers();
	      kv->set_key(ctx.name_);
	      kv->set_value(ctx.value_->getStringView().data(), ctx.value_->getStringView().size());
	    }
	    continue;
	  case cilium::HeaderMatch::REPLACE_ON_MISMATCH:
	    headers.setReferenceKey(header_data.name_, header_data.value_);
	    kv = log_entry.entry_.mutable_http()->add_missing_headers();
	    break;
	  }
	}
	kv->set_key(header_data.name_.get());
	kv->set_value(header_data.value_);  
      }
      return accepted;
    }

    std::vector<Envoy::Http::HeaderUtility::HeaderDataPtr> headers_; // Allowed if empty.
    std::vector<HeaderMatch> header_matches_;
  };

  class L7NetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
  public:
    L7NetworkPolicyRule(const cilium::L7NetworkPolicyRule& rule) : name_(rule.name()) {
      for (const auto& matcher: rule.metadata_rule()) {
	ENVOY_LOG(debug, "Cilium L7NetworkPolicyRule() metadata_rule: {}", matcher.DebugString());
	metadata_matchers_.emplace_back(matcher);
	matchers_.emplace_back(matcher);
      }
    }

    bool matches(const envoy::config::core::v3::Metadata& metadata) const {
      // All matchers must be satisfied for the rule to match
      int i = 0;
      for (const auto& metadata_matcher: metadata_matchers_) {
	ENVOY_LOG(trace, "L7NetworkPolicyRule::matches(): checking rule {} against metadata {}",
		  matchers_[i].DebugString(), metadata.DebugString());
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
      for (const auto& remote: rule.remote_policies()) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {} by rule {}", remote, name_);
	allowed_remotes_.emplace(remote);
      }
      if (rule.has_downstream_tls_context()) {
	auto config = rule.downstream_tls_context();
	envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext context_config;
	auto tls_context = context_config.mutable_common_tls_context();
	if (config.trusted_ca() != "") {
	  auto require_tls_certificate = context_config.mutable_require_client_certificate();
	  require_tls_certificate->set_value(true);
	  auto validation_context = tls_context->mutable_validation_context();
	  auto trusted_ca = validation_context->mutable_trusted_ca();
	  trusted_ca->set_inline_string(config.trusted_ca());
	}
	if (config.certificate_chain() != "") {
	  auto tls_certificate = tls_context->add_tls_certificates();
	  auto certificate_chain = tls_certificate->mutable_certificate_chain();
	  certificate_chain->set_inline_string(config.certificate_chain());
	  if (config.private_key() != "") {
	    auto private_key = tls_certificate->mutable_private_key();
	    private_key->set_inline_string(config.private_key());
	  } else {
	    throw EnvoyException(absl::StrCat("PortNetworkPolicyRule: TLS context has no private key in rule ", name_));
	  }
	} else {
	  throw EnvoyException(absl::StrCat("PortNetworkPolicyRule: TLS context has no certificate chain in rule ", name_));
	}
	for (int i=0; i < config.server_names_size(); i++) {
	  server_names_.emplace_back(config.server_names(i));
	}
	server_config_ = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
            context_config, parent.transport_socket_factory_context_);
	server_context_ = parent.transport_socket_factory_context_.sslContextManager().createSslServerContext(
            parent.transport_socket_factory_context_.scope(), *server_config_, server_names_);
      }
      if (rule.has_upstream_tls_context()) {
	auto config = rule.upstream_tls_context();
	envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext context_config;
	auto tls_context = context_config.mutable_common_tls_context();
	if (config.trusted_ca() != "") {
	  auto validation_context = tls_context->mutable_validation_context();
	  auto trusted_ca = validation_context->mutable_trusted_ca();
	  trusted_ca->set_inline_string(config.trusted_ca());
	} else {
	  throw EnvoyException(absl::StrCat("PortNetworkPolicyRule: Upstream TLS context has no trusted CA in rule ", name_));
	}
	if (config.certificate_chain() != "") {
	  auto tls_certificate = tls_context->add_tls_certificates();
	  auto certificate_chain = tls_certificate->mutable_certificate_chain();
	  certificate_chain->set_inline_string(config.certificate_chain());
	  if (config.private_key() != "") {
	    auto private_key = tls_certificate->mutable_private_key();
	    private_key->set_inline_string(config.private_key());
	  }
	}
	if (config.server_names_size() > 0) {
	  if (config.server_names_size() > 1) {
	    throw EnvoyException(absl::StrCat("PortNetworkPolicyRule: Upstream TLS context has more than one server name in rule ", name_));
	  }
	  context_config.set_sni(config.server_names(1));
	}
	client_config_ = std::make_unique<Extensions::TransportSockets::Tls::ClientContextConfigImpl>(
            context_config, parent.transport_socket_factory_context_);
	client_context_ = parent.transport_socket_factory_context_.sslContextManager().createSslClientContext(
            parent.transport_socket_factory_context_.scope(), *client_config_);
      }
      if (rule.has_http_rules()) {
	for (const auto& http_rule: rule.http_rules().http_rules()) {
	  if (http_rule.header_matches_size() > 0) {
	    have_header_matches_ = true;
	  }
	  http_rules_.emplace_back(http_rule);
	}
      }
      if (l7_proto_.length() > 0 && rule.has_l7_rules()) {
	const auto& ruleset = rule.l7_rules();
	for (const auto& l7_rule: ruleset.l7_deny_rules()) {
	  l7_deny_rules_.emplace_back(l7_rule);
	}
	for (const auto& l7_rule: ruleset.l7_allow_rules()) {
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

    bool Matches(uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
      if (!Matches(remote_id)) {
	return false;
      }
      if (http_rules_.size() > 0) {
	bool matched = false;
	for (const auto& rule: http_rules_) {
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
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::useProxylib(): returning {}", l7_proto_);
	l7_proto = l7_proto_;
	return true;
      }
      return false;
    }

    // Envoy Metadata matcher
    bool allowed(const envoy::config::core::v3::Metadata& metadata) const override {
      for (const auto& rule: l7_deny_rules_) {
	if (rule.matches(metadata)) {
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::allowed(): DENY due to a matching deny rule {}", rule.name_);
	  return false; // request is denied if any deny rule matches
	}
      }
      if (l7_allow_rules_.size() > 0) {
	for (const auto& rule: l7_allow_rules_) {
	  if (rule.matches(metadata)) {
	    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::allowed(): ALLOW due to a matching allow rule {}", rule.name_);
	    return true;
	  }
	}
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::allowed(): DENY due to all {} allow rules mismatching", l7_allow_rules_.size());
	return false;
      }
      ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules::allowed(): default ALLOW due to no allow rules");
      return true; // allowed by default
    }

    Ssl::ContextSharedPtr getServerTlsContext() const override { return server_context_; }
    Ssl::ContextSharedPtr getClientTlsContext() const override { return client_context_; }

    Ssl::ServerContextConfigPtr server_config_;
    std::vector<std::string> server_names_;
    Ssl::ServerContextSharedPtr server_context_;

    Ssl::ClientContextConfigPtr client_config_;
    Ssl::ClientContextSharedPtr client_context_;

    std::string name_;
    std::unordered_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
    std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
    bool have_header_matches_{false};
    std::string l7_proto_{};
    std::vector<L7NetworkPolicyRule> l7_allow_rules_;
    std::vector<L7NetworkPolicyRule> l7_deny_rules_;
  };
  using PortNetworkPolicyRuleConstSharedPtr = std::shared_ptr<const PortNetworkPolicyRule>;

  class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRules(const NetworkPolicyMap& parent, const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
      if (rules.size() == 0) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow everything.");
      }
      for (const auto& it: rules) {
	rules_.emplace_back(std::make_shared<PortNetworkPolicyRule>(parent, it));
	if (rules_.back()->have_header_matches_) {
	  have_header_matches_ = true;
	}
      }
    }

    bool Matches(uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
      // Empty set matches any payload from anyone
      if (rules_.size() == 0) {
	return true;
      }
      bool matched = false;
      for (const auto& rule: rules_) {
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
      for (const auto& rule: rules_) {
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
    PortNetworkPolicy(const NetworkPolicyMap& parent, const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
      for (const auto& it: rules) {
	// Only TCP supported for HTTP
	if (it.protocol() == envoy::config::core::v3::SocketAddress::TCP) {
	  // Port may be zero, which matches any port.
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP policy for port {}", it.port());
	  if (!rules_.emplace(it.port(), PortNetworkPolicyRules(parent, it.rules())).second) {
	    throw EnvoyException("PortNetworkPolicy: Duplicate port number");
	  }
	} else {
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
	}
      }
    }

    bool Matches(uint32_t port, uint64_t remote_id, Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
      bool found_port_rule = false;
      auto it = rules_.find(port);
      if (it != rules_.end()) {
	if (it->second.Matches(remote_id, headers, log_entry)) {
	  return true;
	}
	found_port_rule = true;
      }
      // Check for any rules that wildcard the port
      // Note: Wildcard port makes no sense for an L7 policy, but the policy could be a L3/L4 policy as well.
      it = rules_.find(0);
      if (it != rules_.end()) {
	if (it->second.Matches(remote_id, headers, log_entry)) {
	  return true;
	}
	found_port_rule = true;
      }

      // No policy for the port was found. Cilium always creates a policy for redirects it
      // creates, so the host proxy never gets here. Sidecar gets all the traffic, which we need
      // to pass through since the bpf datapath already allowed it.
      return found_port_rule ? false : true;
    }

    const PortPolicyConstSharedPtr findPortPolicy(uint32_t port, uint64_t remote_id) const {
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
	       Envoy::Http::RequestHeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const override {
    return ingress
      ? ingress_.Matches(port, remote_id, headers, log_entry)
      : egress_.Matches(port, remote_id, headers, log_entry);
  }

  const PortPolicyConstSharedPtr findPortPolicy(bool ingress, uint32_t port, uint64_t remote_id) const override {
    return ingress
      ? ingress_.findPortPolicy(port, remote_id)
      : egress_.findPortPolicy(port, remote_id);
  }

  bool useProxylib(bool ingress, uint32_t port, uint64_t remote_id, std::string& l7_proto) const override {
    const auto& port_policy = findPortPolicy(ingress, port, remote_id);
    if (port_policy != nullptr) {
      return port_policy->useProxylib(l7_proto);
    }
    return false;
  }

  const std::string& conntrackName() const override {
    return conntrack_map_name_;
  }

public:
  std::string conntrack_map_name_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;

private:
  const PortNetworkPolicy ingress_;
  const PortNetworkPolicy egress_;
};

struct ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject {
  std::map<std::string, std::shared_ptr<const PolicyInstanceImpl>> policies_;
};

// Common base constructor
// This is used directly for testing with a file-based subscription
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context)
  : tls_(context.threadLocal().allocateSlot()), validation_visitor_(ProtobufMessage::getNullValidationVisitor()),
    transport_socket_factory_context_(context.getTransportSocketFactoryContext()),
    local_ip_str_(context.localInfo().address()->ip()->addressAsString()),
    is_sidecar_(context.localInfo().nodeName().rfind("sidecar~" , 0) == 0) {
  instance_id_++;
  name_ = "cilium.policymap." + local_ip_str_ + fmt::format(".{}.", instance_id_);
  if (is_sidecar_) {
    name_ += "sidecar.";
  }
  ENVOY_LOG(debug, "NetworkPolicyMap({}) created.", name_);  

  tls_->set([&](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return std::make_shared<ThreadLocalPolicyMap>();
  });
}

// This is used in production
NetworkPolicyMap::NetworkPolicyMap(Server::Configuration::FactoryContext& context, Cilium::CtMapSharedPtr& ct)
  : NetworkPolicyMap(context) {
  ctmap_ = ct;
  scope_ = context.scope().createScope(name_);
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicy",
			    context.localInfo(), context.clusterManager(), context.dispatcher(), context.random(), *scope_, *this);
}

static const std::shared_ptr<const PolicyInstanceImpl> null_instance_impl{nullptr};

const std::shared_ptr<const PolicyInstanceImpl>& NetworkPolicyMap::GetPolicyInstanceImpl(const std::string& endpoint_policy_name) const {
  if (tls_->get().get() == nullptr) {
    ENVOY_LOG(warn, "Cilium L7 NetworkPolicyMap::GetPolicyInstance(): NULL TLS object!");
    return null_instance_impl;
  }
  const ThreadLocalPolicyMap& map = tls_->getTyped<ThreadLocalPolicyMap>();
  auto it = map.policies_.find(endpoint_policy_name);
  if (it == map.policies_.end()) {
    return null_instance_impl;
  }
  return it->second;
}

const std::shared_ptr<const PolicyInstance> NetworkPolicyMap::GetPolicyInstance(const std::string& endpoint_policy_name) const {
  return GetPolicyInstanceImpl(endpoint_policy_name);
}

void NetworkPolicyMap::pause() {
  auto sub = dynamic_cast<GrpcSubscriptionImpl*>(subscription_.get());
  if (sub) {
    sub->pause();
  }
}

void NetworkPolicyMap::resume() {
  auto sub = dynamic_cast<GrpcSubscriptionImpl*>(subscription_.get());
  if (sub) {
    sub->resume();
  }
}

void NetworkPolicyMap::onConfigUpdate(const Protobuf::RepeatedPtrField<ProtobufWkt::Any>& resources, const std::string& version_info) {
  ENVOY_LOG(debug, "NetworkPolicyMap::onConfigUpdate({}), {} resources, version: {}", name_, resources.size(), version_info);

  std::unordered_set<std::string> keeps;
  std::unordered_set<std::string> ct_maps_to_keep;

  // Collect a shared vector of policies to be added
  auto to_be_added = std::make_shared<std::vector<std::shared_ptr<PolicyInstanceImpl>>>();
  for (const auto& resource: resources) {
    auto config = MessageUtil::anyConvert<cilium::NetworkPolicy>(resource);
    ENVOY_LOG(debug, "Received Network Policy for endpoint {} in onConfigUpdate() version {}", config.name(), version_info);
    keeps.insert(config.name());
    ct_maps_to_keep.insert(config.conntrack_map_name());

    MessageUtil::validate(config, validation_visitor_);

    // First find the old config to figure out if an update is needed.
    const uint64_t new_hash = MessageUtil::hash(config);
    const auto& old_policy = GetPolicyInstanceImpl(config.name());
    if (old_policy && old_policy->hash_ == new_hash &&
	Protobuf::util::MessageDifferencer::Equals(old_policy->policy_proto_, config)) {
      ENVOY_LOG(trace, "New policy is equal to old one, not updating.");
      continue;
    }

    // May throw
    to_be_added->emplace_back(std::make_shared<PolicyInstanceImpl>(*this, new_hash, config));
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

  // pause the subscription until the worker threads are done. No throws after this!
  ENVOY_LOG(trace, "Pausing NPDS subscription");
  pause();

  // 'this' may be already deleted when the worker threads get to execute the updates.
  // Manage this by taking a shared_ptr on 'this' for the duration of the posted lambda.
  std::shared_ptr<NetworkPolicyMap> shared_this = shared_from_this();

  // Execute changes on all threads.
  tls_->runOnAllThreads([shared_this, to_be_added, to_be_deleted]() -> void {
      if (shared_this->tls_->get().get() != nullptr) {
	ENVOY_LOG(trace, "Cilium L7 NetworkPolicyMap::onConfigUpdate(): Starting updates on the next thread");
	auto& npmap = shared_this->tls_->getTyped<ThreadLocalPolicyMap>().policies_;
	for (const auto& policy_name: *to_be_deleted) {
	  ENVOY_LOG(trace, "Cilium deleting removed network policy for endpoint {}", policy_name);
	  npmap.erase(policy_name);
	}
	for (const auto& new_policy: *to_be_added) {
	  ENVOY_LOG(trace, "Cilium updating network policy for endpoint {}", new_policy->policy_proto_.name());
	  npmap[new_policy->policy_proto_.name()] = new_policy;
	}
      } else {
	// Keep this at info level for now to see if this happens in the wild
	ENVOY_LOG(warn, "Skipping stale network policy update");
      }
    },
    // resume NPDS and delete old cts when all threads have updated their policies
    [shared_this, cts_to_be_closed]() -> void {
      // resume the subscription
      ENVOY_LOG(trace, "Resuming NPDS subscription");
      shared_this->resume();
      if (shared_this->ctmap_ && shared_this->tls_->get().get() != nullptr && cts_to_be_closed->size() > 0) {
	shared_this->ctmap_->closeMaps(cts_to_be_closed);
      }
    });
}

void NetworkPolicyMap::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason, const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
  ENVOY_LOG(debug, "Network Policy Update failed, keeping existing policy." );
}

} // namespace Cilium
} // namespace Envoy
