#pragma once

#include <arpa/inet.h>
#include <fmt/format.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/config/subscription.h"
#include "envoy/network/address.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"
#include "envoy/stats/scope.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/thread_local/thread_local_object.h"

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"
#include "source/common/network/utility.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/protobuf.h"
#include "source/common/protobuf/utility.h"

#include "absl/container/flat_hash_map.h"
#include "absl/numeric/int128.h"
#include "absl/status/status.h"
#include "cilium/api/nphds.pb.h"
#include "cilium/api/nphds.pb.validate.h" // IWYU pragma: keep
#include "cilium/policy_id.h"

// std::hash specialization for Abseil uint128, needed for unordered_map key.
namespace std {
template <> struct hash<absl::uint128> {
  size_t operator()(const absl::uint128& x) const {
    return hash<uint64_t>{}(absl::Uint128Low64(x)) ^
           (hash<uint64_t>{}(absl::Uint128High64(x)) << 1);
  }
};
} // namespace std

namespace Envoy {
namespace Cilium {

template <typename I> I ntoh(I);
template <> inline uint32_t ntoh(uint32_t addr) { return ntohl(addr); }
template <> inline absl::uint128 ntoh(absl::uint128 addr) {
  return Network::Utility::Ip6ntohl(addr);
}
template <typename I> I hton(I);
template <> inline uint32_t hton(uint32_t addr) { return htonl(addr); }
template <> inline absl::uint128 hton(absl::uint128 addr) {
  return Network::Utility::Ip6htonl(addr);
}

template <typename I> I masked(I addr, unsigned int plen) {
  const unsigned int plen_max = sizeof(I) * 8;
  return plen == 0 ? I(0) : addr & ~hton((I(1) << (plen_max - plen)) - 1);
};

class PolicyHostDecoder : public Envoy::Config::OpaqueResourceDecoder {
public:
  PolicyHostDecoder() : validation_visitor_(ProtobufMessage::getNullValidationVisitor()) {}

  // Config::OpaqueResourceDecoder
  ProtobufTypes::MessagePtr decodeResource(const ProtobufWkt::Any& resource) override {
    auto typed_message = std::make_unique<cilium::NetworkPolicyHosts>();
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

class PolicyHostMap : public Singleton::Instance,
                      public Config::SubscriptionCallbacks,
                      public std::enable_shared_from_this<PolicyHostMap>,
                      public Logger::Loggable<Logger::Id::config> {
public:
  PolicyHostMap(Server::Configuration::CommonFactoryContext& context);
  PolicyHostMap(ThreadLocal::SlotAllocator& tls);
  ~PolicyHostMap() override {
    ENVOY_LOG(debug, "Cilium PolicyHostMap({}): PolicyHostMap is deleted NOW!", name_);
  }

  void startSubscription(Server::Configuration::CommonFactoryContext& context);

  // This is used for testing with a file-based subscription
  void startSubscription(std::unique_ptr<Envoy::Config::Subscription>&& subscription) {
    subscription_ = std::move(subscription);
    subscription_->start({});
  }

  // A shared pointer to a immutable copy is held by each thread. Changes are
  // done by creating a new version and assigning the new shared pointer to the
  // thread local slot on each thread.
  struct ThreadLocalHostMap : public ThreadLocal::ThreadLocalObject,
                              public Logger::Loggable<Logger::Id::config> {
  public:
    void logmaps(const std::string& msg) const {
      char buf[INET6_ADDRSTRLEN];
      std::string ip4, ip6, prefix;
      bool first = true;
      for (const auto& mask : ipv4_to_policy_) {
        std::string prefix = fmt::format("{}", mask.first);
        for (const auto& pair : mask.second) {
          if (!first) {
            ip4 += ", ";
          }
          first = false;
          ip4 += fmt::format("{}/{}->{}", inet_ntop(AF_INET, &pair.first, buf, sizeof(buf)), prefix,
                             pair.second);
        }
      }
      first = true;
      for (const auto& mask : ipv6_to_policy_) {
        std::string prefix = fmt::format("{}", mask.first);
        for (const auto& pair : mask.second) {
          if (!first) {
            ip6 += ", ";
          }
          first = false;
          ip6 += fmt::format("{}/{}->{}", inet_ntop(AF_INET6, &pair.first, buf, sizeof(buf)),
                             prefix, pair.second);
        }
      }
      ENVOY_LOG(debug, "PolicyHostMap::{}: IPv4: [{}], IPv6: [{}]", msg, ip4, ip6);
    }

    // Find the longest prefix match of the addr, return the matching policy id,
    // or ID::WORLD if there is no match.
    uint64_t resolve(uint32_t addr4) const {
      for (const auto& pair : ipv4_to_policy_) {
        auto it = pair.second.find(masked(addr4, pair.first));
        if (it != pair.second.end()) {
          return it->second;
        }
      }
      return ID::Unknown;
    }

    uint64_t resolve(absl::uint128 addr6) const {
      for (const auto& pair : ipv6_to_policy_) {
        auto it = pair.second.find(masked(addr6, pair.first));
        if (it != pair.second.end()) {
          return it->second;
        }
      }
      return ID::Unknown;
    }

    uint64_t resolve(const Network::Address::Ip* addr) const {
      auto* ipv4 = addr->ipv4();
      if (ipv4) {
        return resolve(ipv4->address());
      }
      auto* ipv6 = addr->ipv6();
      if (ipv6) {
        return resolve(ipv6->address());
      }
      return ID::World;
    }

  protected:
    // Vectors of <prefix-len>, <address-map> pairs, ordered in the decreasing
    // prefix length, where map keys are addresses of the given prefix length.
    // Address bits outside of the prefix are zeroes.
    std::vector<std::pair<unsigned int, absl::flat_hash_map<uint32_t, uint64_t>>> ipv4_to_policy_;
    std::vector<std::pair<unsigned int, absl::flat_hash_map<absl::uint128, uint64_t>>>
        ipv6_to_policy_;
  };
  using ThreadLocalHostMapSharedPtr = std::shared_ptr<ThreadLocalHostMap>;

  const ThreadLocalHostMap* getHostMap() const {
    return tls_->get().get() ? &tls_->getTyped<ThreadLocalHostMap>() : nullptr;
  }

  uint64_t resolve(const Network::Address::Ip* addr) const {
    const ThreadLocalHostMap* hostmap = getHostMap();
    return (hostmap != nullptr) ? hostmap->resolve(addr) : ID::Unknown;
  }

  void logmaps(const std::string& msg) {
    if (ENVOY_LOG_CHECK_LEVEL(debug)) {
      auto tlsmap = getHostMap();
      if (tlsmap) {
        tlsmap->logmaps(msg);
      } else {
        ENVOY_LOG(debug, "PolicyHostMap::{}: Error getting thread local map", msg);
      }
    }
  }

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

private:
  ThreadLocal::SlotPtr tls_;
  Stats::ScopeSharedPtr scope_;
  std::unique_ptr<Envoy::Config::Subscription> subscription_;
  static uint64_t instance_id_;
  std::string name_;
};

} // namespace Cilium
} // namespace Envoy
