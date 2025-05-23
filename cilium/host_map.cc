#include "cilium/host_map.h"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/config/subscription.h"
#include "envoy/event/dispatcher.h"
#include "envoy/server/factory_context.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/thread_local/thread_local_object.h"

#include "source/common/common/logger.h"
#include "source/common/common/macros.h"

#include "absl/numeric/int128.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "cilium/api/nphds.pb.h"
#include "cilium/grpc_subscription.h"

namespace Envoy {
namespace Cilium {

template <typename T>
unsigned int checkPrefix(T addr, bool have_prefix, unsigned int plen, absl::string_view host) {
  const unsigned int plen_max = sizeof(T) * 8;
  if (!have_prefix) {
    return plen_max;
  }
  if (plen > plen_max) {
    throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
  }
  // Check for 1-bits after the prefix
  if ((plen == 0 && addr) || (plen > 0 && addr & ntoh((T(1) << (plen_max - plen)) - 1))) {
    throw EnvoyException(fmt::format("NetworkPolicyHosts: Non-prefix bits set in \'{}\'", host));
  }
  return plen;
}

struct ThreadLocalHostMapInitializer : public PolicyHostMap::ThreadLocalHostMap {
protected:
  friend class PolicyHostMap; // PolicyHostMap can insert();

  // find the map of the given prefix length, insert in the decreasing order if
  // it does not exist
  template <typename M>
  M& getMap(std::vector<std::pair<unsigned int, M>>& maps, unsigned int plen) {
    auto it = maps.begin();
    for (; it != maps.end(); it++) {
      if (it->first > plen) {
        ENVOY_LOG(trace, "Skipping map for prefix length {} while looking for {}", it->first, plen);
        continue; // check the next one
      }
      if (it->first == plen) {
        ENVOY_LOG(trace, "Found existing map for prefix length {}", plen);
        return it->second;
      }
      // Current pair has smaller prefix, insert before it to maintain order
      ENVOY_LOG(trace, "Inserting map for prefix length {} before prefix length {}", plen,
                it->first);
      break;
    }
    // not found, insert before the position 'it'
    ENVOY_LOG(trace, "Inserting map for prefix length {}", plen);
    return maps.emplace(it, std::make_pair(plen, M{}))->second;
  }

  bool insert(uint32_t addr, unsigned int plen, uint64_t policy) {
    auto pair = getMap(ipv4_to_policy_, plen).emplace(std::make_pair(addr, policy));
    return pair.second;
  }

  bool insert(absl::uint128 addr, unsigned int plen, uint64_t policy) {
    auto pair = getMap(ipv6_to_policy_, plen).emplace(std::make_pair(addr, policy));
    return pair.second;
  }

  void insert(const cilium::NetworkPolicyHosts& proto) {
    uint64_t policy = proto.policy();
    const auto& hosts = proto.host_addresses();
    std::string buf;

    for (const auto& host : hosts) {
      const char* addr = host.c_str();
      unsigned int plen = 0;

      ENVOY_LOG(trace, "NetworkPolicyHosts: Inserting CIDR->ID mapping {}->{}...", host, policy);

      // Find the prefix length if any
      const char* slash = strchr(addr, '/');
      bool have_prefix = (slash != nullptr);
      if (have_prefix) {
        const char* pstr = slash + 1;
        // Must start with a digit and have nothing after a zero.
        if (*pstr < '0' || *pstr > '9' || (*pstr == '0' && *(pstr + 1) != '\0')) {
          throw EnvoyException(
              fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
        }
        // Convert to base 10 integer as long as there are digits and plen is
        // not too large. If plen is already 13, next digit will make it at
        // least 130, which is too much.
        while (*pstr >= '0' && *pstr <= '9' && plen < 13) {
          plen = plen * 10 + (*pstr++ - '0');
        }
        if (*pstr != '\0') {
          throw EnvoyException(
              fmt::format("NetworkPolicyHosts: Invalid prefix length in \'{}\'", host));
        }
        // Copy the address without the prefix
        buf.assign(addr, slash);
        addr = buf.c_str();
      }

      uint32_t addr4;
      int rc = inet_pton(AF_INET, addr, &addr4);
      if (rc == 1) {
        plen = checkPrefix(addr4, have_prefix, plen, host);
        if (!insert(addr4, plen, policy)) {
          uint64_t existing_policy = resolve(addr4);
          throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry \'{}\' for "
                                           "policy {}, already mapped to {}",
                                           host, policy, existing_policy));
        }
        continue;
      }
      absl::uint128 addr6;
      rc = inet_pton(AF_INET6, addr, &addr6);
      if (rc == 1) {
        plen = checkPrefix(addr6, have_prefix, plen, host);
        if (!insert(addr6, plen, policy)) {
          uint64_t existing_policy = resolve(addr6);
          throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry \'{}\' for "
                                           "policy {}, already mapped to {}",
                                           host, policy, existing_policy));
        }
        continue;
      }
      throw EnvoyException(
          fmt::format("NetworkPolicyHosts: Invalid host entry \'{}\' for policy {}", host, policy));
    }
  }
};

uint64_t PolicyHostMap::instance_id_ = 0;

// This is used directly for testing with a file-based subscription
PolicyHostMap::PolicyHostMap(ThreadLocal::SlotAllocator& tls) : tls_(tls.allocateSlot()) {
  instance_id_++;
  name_ = "cilium.hostmap." + fmt::format("{}", instance_id_) + ".";
  ENVOY_LOG(debug, "PolicyHostMap({}) created.", name_);

  auto empty_map = std::make_shared<ThreadLocalHostMapInitializer>();
  tls_->set([empty_map](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return empty_map;
  });
}

// This is used in production
PolicyHostMap::PolicyHostMap(Server::Configuration::CommonFactoryContext& context)
    : PolicyHostMap(context.threadLocal()) {
  scope_ = context.serverScope().createScope(name_);
}

void PolicyHostMap::startSubscription(Server::Configuration::CommonFactoryContext& context) {
  subscription_ = subscribe("type.googleapis.com/cilium.NetworkPolicyHosts", context.localInfo(),
                            context.clusterManager(), context.mainThreadDispatcher(),
                            context.api().randomGenerator(), *scope_, *this,
                            std::make_shared<Cilium::PolicyHostDecoder>());
  subscription_->start({});
}

absl::Status
PolicyHostMap::onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) {
  ENVOY_LOG(debug, "PolicyHostMap::onConfigUpdate({}), {} resources, version: {}", name_,
            resources.size(), version_info);

  auto newmap = std::make_shared<ThreadLocalHostMapInitializer>();

  for (const auto& resource : resources) {
    const auto& config = dynamic_cast<const cilium::NetworkPolicyHosts&>(resource.get().resource());
    ENVOY_LOG(trace,
              "Received NetworkPolicyHosts for policy {} in onConfigUpdate() "
              "version {}",
              config.policy(), version_info);
    newmap->insert(config);
  }

  // Force 'this' to be not deleted for as long as the lambda stays
  // alive. Note that generally capturing a shared pointer is
  // dangerous as it may happen that there is a circular reference
  // from 'this' to itself via the lambda capture, leading to 'this'
  // never being released. It should happen in this case, though.
  std::shared_ptr<PolicyHostMap> shared_this = shared_from_this();

  // Assign the new map to all threads.
  tls_->set([shared_this, newmap](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    UNREFERENCED_PARAMETER(shared_this);
    ENVOY_LOG(trace, "PolicyHostMap: Assigning new map");
    return newmap;
  });
  logmaps("onConfigUpdate");
  return absl::OkStatus();
}

void PolicyHostMap::onConfigUpdateFailed(Envoy::Config::ConfigUpdateFailureReason,
                                         const EnvoyException*) {
  // We need to allow server startup to continue, even if we have a bad
  // config.
}

} // namespace Cilium
} // namespace Envoy
