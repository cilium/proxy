#pragma once

#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/config/subscription.h"
#include "envoy/network/address.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats_macros.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/thread_local/thread_local_object.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/arena_wrapped_proto.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"

#include "absl/status/status.h"
#include "cilium/api/nphds.pb.h"
#include "cilium/api/nphds.pb.validate.h" // IWYU pragma: keep
#include "cilium/grpc_subscription.h"
#include "cilium/host_map.h"
#include "cilium/policy_id.h"

namespace Envoy {
namespace Cilium {

class PolicyHostDecoder : public Envoy::Config::OpaqueResourceDecoder {
public:
  PolicyHostDecoder() : validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {}

  // Config::OpaqueResourceDecoder
  ArenaWrappedProto<Protobuf::Message> decodeResource(const Protobuf::Any& resource) override {
    ArenaWrappedProto<cilium::NetworkPolicyHosts> typed_message;
    // If the Any is a synthetic empty message (e.g. because the resource field
    // was not set in Resource, this might be empty, so we shouldn't decode.
    if (!resource.type_url().empty()) {
      MessageUtil::anyConvertAndValidate<cilium::NetworkPolicyHosts>(resource, *typed_message,
                                                                     validation_visitor_);
    }
    return typed_message;
  }

  std::string resourceName(const Protobuf::Message& resource) override {
    return fmt::format("{}", dynamic_cast<const cilium::NetworkPolicyHosts&>(resource).policy());
  }

private:
  ProtobufMessage::ValidationVisitor& validation_visitor_;
};

// clang-format off
#define CILIUM_POLICY_HOSTS_STATS(COUNTER)	\
  COUNTER(update_success)
// clang-format on

/**
 * Struct definition for all policy stats. @see stats_macros.h
 */
struct PolicyHostsStats {
  CILIUM_POLICY_HOSTS_STATS(GENERATE_COUNTER_STRUCT)
};

// NPHDS subscription publishing shared immutable HostMap snapshots to worker slots.
class PolicyHostMap : public Singleton::Instance, public ManagedGrpcSubscription {
public:
  PolicyHostMap(Server::Configuration::CommonFactoryContext& context,
                const envoy::config::core::v3::ConfigSource& config_source, bool subscribe = true);
  ~PolicyHostMap() override {
    ENVOY_LOG(debug, "Cilium PolicyHostMap({}): PolicyHostMap is deleted NOW!", name_);
  }

  uint64_t resolve(const Network::Address::Ip* addr) const {
    const HostMap* hostmap = getHostMap();
    return hostmap != nullptr ? hostmap->resolve(addr) : ID::UNKNOWN;
  }

  // Config::SubscriptionCallbacks
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) override;
  absl::Status onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) override;

private:
  const HostMap* getHostMap() const {
    return tls_->get().get() ? &tls_->getTyped<ThreadLocalHostMap>().hosts_ : nullptr;
  }

  void logmaps(const std::string& msg) {
    if (ENVOY_LOG_CHECK_LEVEL(debug)) {
      const auto* hostmap = getHostMap();
      if (hostmap != nullptr) {
        hostmap->logmaps(msg);
      } else {
        ENVOY_LOG(debug, "PolicyHostMap::{}: Error getting thread local map", msg);
      }
    }
  }

  struct ThreadLocalHostMap : public ThreadLocal::ThreadLocalObject {
    explicit ThreadLocalHostMap(HostMap&& hosts) : hosts_(std::move(hosts)) {}

    const HostMap hosts_;
  };

  ThreadLocal::SlotSharedPtr tls_;
  std::string name_;
  uint64_t accepted_stream_generation_{0};
  static uint64_t instance_id_;
  Stats::ScopeSharedPtr host_stats_scope_;
  PolicyHostsStats stats_;
};

} // namespace Cilium
} // namespace Envoy
