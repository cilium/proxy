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
#include "envoy/server/filter_config.h"
#include "server/transport_socket_config_impl.h"

#include "extensions/transport_sockets/tls/context_config_impl.h"

#include "cilium/api/npds.pb.h"
#include "cilium/accesslog.h"
#include "cilium/conntrack.h"

namespace Envoy {
namespace Cilium {

class PolicyInstance;

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
  void startSubscription() { subscription_->start({}); }

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
    startSubscription();
  }

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
  void pause();
  void resume();
  
  ThreadLocal::SlotPtr tls_;
  ProtobufMessage::ValidationVisitor& validation_visitor_;
  Stats::ScopePtr scope_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  const std::shared_ptr<const PolicyInstance> null_instance_{nullptr};
  static uint64_t instance_id_;
  std::string name_;
  Cilium::CtMapSharedPtr ctmap_;
public:
  Server::Configuration::TransportSocketFactoryContext& transport_socket_factory_context_;
};

class PolicyInstance {
public:
  PolicyInstance(const NetworkPolicyMap& parent, uint64_t hash, const cilium::NetworkPolicy& proto)
    : conntrack_map_name_(proto.conntrack_map_name()), hash_(hash), policy_proto_(proto),
      ingress_(parent, policy_proto_.ingress_per_port_policies()),
      egress_(parent, policy_proto_.egress_per_port_policies()) {}

  std::string conntrack_map_name_;
  uint64_t hash_;
  const cilium::NetworkPolicy policy_proto_;

protected:
  class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    static envoy::api::v2::route::HeaderMatcher matcher(const cilium::HeaderMatch& config) {
      envoy::api::v2::route::HeaderMatcher match;
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

    bool Matches(const Envoy::Http::HeaderMap& headers) const {
      // Empty set matches any headers.
      return Envoy::Http::HeaderUtility::matchHeaders(headers, headers_);
    }

    // Should only be called after 'Matches' returns 'true'.
    // Returns 'true' if matching can continue
    bool HeaderMatches(Envoy::Http::HeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
      bool accepted = true;
      for (const auto& header_data : header_matches_) {
	::cilium::KeyValue *kv;
	if (Envoy::Http::HeaderUtility::matchHeaders(headers, header_data)) {
	  // Match action
	  ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():HeaderMatches: match, {}: {}: Action {}",
		    header_data.name_.get(), header_data.value_, header_data.match_action_);
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
	  kv = log_entry.entry.mutable_http()->add_rejected_headers();
	} else {
	  // Mismatch action
	  ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():HeaderMatches: no match, imposing header {}: {}: Action {}",
		    header_data.name_.get(), header_data.value_, header_data.mismatch_action_);
	  switch (header_data.mismatch_action_) {
	  case cilium::HeaderMatch::FAIL_ON_MISMATCH:
	  default:
	    kv = log_entry.entry.mutable_http()->add_missing_headers();
	    accepted = false;
	    break;
	  case cilium::HeaderMatch::CONTINUE_ON_MISMATCH:
	    kv = log_entry.entry.mutable_http()->add_missing_headers();
	    continue;
	  case cilium::HeaderMatch::ADD_ON_MISMATCH:
	    headers.addReferenceKey(header_data.name_, header_data.value_);
	    kv = log_entry.entry.mutable_http()->add_missing_headers();
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
		res == Envoy::Http::HeaderMap::Lookup::Found ? &entry->value() : nullptr
	      };
	      if (res == Envoy::Http::HeaderMap::Lookup::NotSupported) {
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
	      kv = log_entry.entry.mutable_http()->add_rejected_headers();
	      kv->set_key(ctx.name_);
	      kv->set_value(ctx.value_->getStringView().data(), ctx.value_->getStringView().size());
	    }
	    continue;
	  case cilium::HeaderMatch::REPLACE_ON_MISMATCH:
	    headers.setReferenceKey(header_data.name_, header_data.value_);
	    kv = log_entry.entry.mutable_http()->add_missing_headers();
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

  class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRule(const NetworkPolicyMap& parent, const cilium::PortNetworkPolicyRule& rule)
      : l7_proto_(rule.l7_proto()) {
      for (const auto& remote: rule.remote_policies()) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {}", remote);
	allowed_remotes_.emplace(remote);
      }
      if (rule.has_downstream_tls_context()) {
	auto config = rule.downstream_tls_context();
	envoy::api::v2::auth::DownstreamTlsContext context_config;
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
	    throw EnvoyException("PortNetworkPolicyRule: TLS context has no private key");
	  }
	} else {
	  throw EnvoyException("PortNetworkPolicyRule: TLS context has no certificate chain");
	}
	for (int i=0; i < config.server_names_size(); i++) {
	  server_names_.emplace_back(config.server_names(i));
	}
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Server TLS context: {}", context_config.DebugString());
	server_config_ = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
            context_config, parent.transport_socket_factory_context_);
	server_context_ = parent.transport_socket_factory_context_.sslContextManager().createSslServerContext(
            parent.transport_socket_factory_context_.scope(), *server_config_, server_names_);
      }
      if (rule.has_upstream_tls_context()) {
	auto config = rule.upstream_tls_context();
	envoy::api::v2::auth::UpstreamTlsContext context_config;
	auto tls_context = context_config.mutable_common_tls_context();
	if (config.trusted_ca() != "") {
	  auto validation_context = tls_context->mutable_validation_context();
	  auto trusted_ca = validation_context->mutable_trusted_ca();
	  trusted_ca->set_inline_string(config.trusted_ca());
	} else {
	  throw EnvoyException("PortNetworkPolicyRule: Upstream TLS context has no trusted CA: {}");
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
	    throw EnvoyException("PortNetworkPolicyRule: Upstream TLS context has more than one server name");
	  }
	  context_config.set_sni(config.server_names(1));
	}
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Client TLS context: {}", context_config.DebugString());
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

    bool Matches(uint64_t remote_id, Envoy::Http::HeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
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

    bool useProxylib(std::string& l7_proto) const {
      if (l7_proto_.length() > 0) {
	ENVOY_LOG(debug, "Cilium L7 PortNetworkPolicyRules::useProxylib(): returning {}", l7_proto_);
	l7_proto = l7_proto_;
	return true;
      }
      return false;
    }

    Ssl::ContextSharedPtr getServerTlsContext() const {
      return server_context_;
    }

    Ssl::ContextSharedPtr getClientTlsContext() const {
      return client_context_;
    }

    Ssl::ServerContextConfigPtr server_config_;
    std::vector<std::string> server_names_;
    Ssl::ServerContextSharedPtr server_context_;

    Ssl::ClientContextConfigPtr client_config_;
    Ssl::ClientContextSharedPtr client_context_;

    std::unordered_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
    std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
    std::string l7_proto_{};
    int have_header_matches_{false};
  };

  class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
  public:
    PortNetworkPolicyRules(const NetworkPolicyMap& parent, const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) {
      if (rules.size() == 0) {
	ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow everything.");
      }
      for (const auto& it: rules) {
	if (it.has_http_rules()) {
	  have_http_rules_ = true;
	}
	rules_.emplace_back(parent, it);
      }
    }

    bool Matches(uint64_t remote_id, Envoy::Http::HeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
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
	if (rule.Matches(remote_id, headers, log_entry)) {
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
    PortNetworkPolicy(const NetworkPolicyMap& parent, const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
      for (const auto& it: rules) {
	// Only TCP supported for HTTP
	if (it.protocol() == envoy::api::v2::core::SocketAddress::TCP) {
	  // Port may be zero, which matches any port.
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP policy for port {}", it.port());
	  if (!rules_.emplace(it.port(), PortNetworkPolicyRules(parent, it.rules())).second) {
	    throw EnvoyException("PortNetworkPolicy: Duplicate port number");
	  }
	} else {
	  ENVOY_LOG(debug, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
	}
      }
    }

    bool Matches(uint32_t port, uint64_t remote_id, Envoy::Http::HeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
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
	       Envoy::Http::HeaderMap& headers, Cilium::AccessLog::Entry& log_entry) const {
    return ingress
      ? ingress_.Matches(port, remote_id, headers, log_entry)
      : egress_.Matches(port, remote_id, headers, log_entry);
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
