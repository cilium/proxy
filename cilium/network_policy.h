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
#include "source/extensions/transport_sockets/tls/context_config_impl.h"
#include "source/server/transport_socket_config_impl.h"

#include "cilium/accesslog.h"
#include "cilium/api/npds.pb.h"
#include "cilium/api/npds.pb.validate.h"
#include "cilium/conntrack.h"

namespace Envoy {
namespace Cilium {

class PortPolicy {
public:
  virtual ~PortPolicy() = default;

  virtual bool useProxylib(std::string& l7_proto) const PURE;

  virtual bool Matches(absl::string_view sni, uint32_t remote_id) const PURE;

  virtual bool allowed(const envoy::config::core::v3::Metadata& metadata) const PURE;

  virtual const Ssl::ContextConfig& getServerTlsContextConfig() const PURE;
  virtual Ssl::ContextSharedPtr getServerTlsContext() const PURE;
  virtual const Ssl::ContextConfig& getClientTlsContextConfig() const PURE;
  virtual Ssl::ContextSharedPtr getClientTlsContext() const PURE;
};
using PortPolicyConstSharedPtr = std::shared_ptr<const PortPolicy>;

class IPAddressPair {
public:
  IPAddressPair(){};
  IPAddressPair(const cilium::NetworkPolicy& proto);

  Network::Address::InstanceConstSharedPtr ipv4_{};
  Network::Address::InstanceConstSharedPtr ipv6_{};
};

class PolicyInstance {
public:
  virtual ~PolicyInstance() = default;

  virtual bool Allowed(bool ingress, uint16_t port, uint32_t remote_id,
                       Envoy::Http::RequestHeaderMap& headers,
                       Cilium::AccessLog::Entry& log_entry) const PURE;

  virtual const PortPolicyConstSharedPtr findPortPolicy(bool ingress, uint16_t port,
                                                        uint32_t remote_id) const PURE;

  // Returns true if the policy specifies l7 protocol for the connection, and
  // returns the l7 protocol string in 'l7_proto'
  virtual bool useProxylib(bool ingress, uint16_t port, uint32_t remote_id,
                           std::string& l7_proto) const PURE;

  virtual const std::string& conntrackName() const PURE;

  virtual uint32_t getEndpointID() const PURE;

  virtual const IPAddressPair& getEndpointIPs() const PURE;
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
  void startSubscription(Server::Configuration::FactoryContext& context);

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
  void onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                      const std::string& version_info) override;
  void onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                      const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                      const std::string& system_version_info) override {
    // NOT IMPLEMENTED YET.
    UNREFERENCED_PARAMETER(added_resources);
    UNREFERENCED_PARAMETER(removed_resources);
    UNREFERENCED_PARAMETER(system_version_info);
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

  static uint64_t instance_id_;

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

public:
  const bool is_sidecar_;
};

} // namespace Cilium
} // namespace Envoy
