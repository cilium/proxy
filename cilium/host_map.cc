#include "cilium/host_map.h"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/common/exception.h"
#include "envoy/network/address.h"

#include "source/common/common/logger.h"
#include "source/common/network/utility.h"

#include "absl/container/flat_hash_set.h"
#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "cilium/policy_id.h"

namespace Envoy {
namespace Cilium {
namespace {

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

template <typename T>
unsigned int checkPrefix(T addr, bool have_prefix, unsigned int plen, absl::string_view host) {
  const unsigned int plen_max = sizeof(T) * 8;
  if (!have_prefix) {
    return plen_max;
  }
  if (plen > plen_max) {
    throw EnvoyException(fmt::format("Invalid prefix length in \'{}\'", host));
  }
  // Check for 1-bits after the prefix
  if ((plen == 0 && addr) || (plen > 0 && addr & ntoh((T(1) << (plen_max - plen)) - 1))) {
    throw EnvoyException(fmt::format("Non-prefix bits set in \'{}\'", host));
  }
  return plen;
}

} // namespace

NamedPortsConstSharedPtr makeNamedPorts(NamedPorts named_ports) {
  if (named_ports.empty()) {
    return nullptr;
  }
  std::ranges::sort(named_ports, [](const NamedPort& lhs, const NamedPort& rhs) {
    return lhs.name_ < rhs.name_ || (lhs.name_ == rhs.name_ && lhs.port_ < rhs.port_);
  });
  named_ports.erase(std::ranges::unique(named_ports).begin(), named_ports.end());
  return std::make_shared<const NamedPorts>(std::move(named_ports));
}

const PolicyInfo& HostMap::unknownPolicyInfo() {
  static const PolicyInfo info{ID::UNKNOWN};
  return info;
}

const PolicyInfo& HostMap::worldPolicyInfo() {
  static const PolicyInfo info{ID::WORLD};
  return info;
}

HostMapBuilder::HostMapBuilder(const HostMap* host_map) {
  if (host_map != nullptr) {
    static_cast<HostMap&>(*this) = *host_map;
  }
}

// find the map of the given prefix length, insert in the decreasing order if
// it does not exist
template <typename M>
M& HostMapBuilder::getMap(std::vector<std::pair<unsigned int, M>>& maps, unsigned int plen) {
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
    ENVOY_LOG(trace, "Inserting map for prefix length {} before prefix length {}", plen, it->first);
    break;
  }
  // not found, insert before the position 'it'
  ENVOY_LOG(trace, "Inserting map for prefix length {}", plen);
  return maps.emplace(it, std::make_pair(plen, M{}))->second;
}

void HostMapBuilder::insert(uint64_t policy, const Protobuf::RepeatedPtrField<std::string>& hosts,
                            NamedPorts named_ports) {
  PolicyInfo info{policy, std::move(named_ports)};

  std::string buf;
  for (const auto& host : hosts) {
    const char* addr = host.c_str();
    unsigned int plen = 0;

    ENVOY_LOG(trace, "Inserting CIDR->ID mapping {}->{}...", host, policy);

    // Find the prefix length if any
    const char* slash = strchr(addr, '/');
    bool have_prefix = (slash != nullptr);
    if (have_prefix) {
      const char* pstr = slash + 1;
      // Must start with a digit and have nothing after a zero.
      if (*pstr < '0' || *pstr > '9' || (*pstr == '0' && *(pstr + 1) != '\0')) {
        throw EnvoyException(fmt::format("Invalid prefix length in \'{}\'", host));
      }
      // Convert to base 10 integer as long as there are digits and plen is
      // not too large. If plen is already 13, next digit will make it at
      // least 130, which is too much.
      while (*pstr >= '0' && *pstr <= '9' && plen < 13) {
        plen = plen * 10 + (*pstr++ - '0');
      }
      if (*pstr != '\0') {
        throw EnvoyException(fmt::format("Invalid prefix length in \'{}\'", host));
      }
      // Copy the address without the prefix
      buf.assign(addr, slash);
      addr = buf.c_str();
    }

    uint32_t addr4;
    int rc = inet_pton(AF_INET, addr, &addr4);
    if (rc == 1) {
      plen = checkPrefix(addr4, have_prefix, plen, host);
      if (!getMap(ipv4_to_policy_, plen).emplace(addr4, info).second) {
        uint64_t existing_policy = resolve(addr4).identity_;
        throw EnvoyException(fmt::format("Duplicate host entry \'{}\' for "
                                         "policy {}, already mapped to {}",
                                         host, policy, existing_policy));
      }
      continue;
    }
    absl::uint128 addr6;
    rc = inet_pton(AF_INET6, addr, &addr6);
    if (rc == 1) {
      plen = checkPrefix(addr6, have_prefix, plen, host);
      if (!getMap(ipv6_to_policy_, plen).emplace(addr6, info).second) {
        uint64_t existing_policy = resolve(addr6).identity_;
        throw EnvoyException(fmt::format("Duplicate host entry \'{}\' for "
                                         "policy {}, already mapped to {}",
                                         host, policy, existing_policy));
      }
      continue;
    }
    throw EnvoyException(fmt::format("Invalid host entry \'{}\' for policy {}", host, policy));
  }
}

template <typename MapVec>
void HostMapBuilder::prunePolicyMapVec(MapVec& maps, const absl::flat_hash_set<uint64_t>& nids) {
  for (auto vec_it = maps.begin(); vec_it != maps.end();) {
    auto& map = vec_it->second;
    for (auto map_it = map.begin(); map_it != map.end();) {
      auto it = map_it++;
      if (nids.contains(it->second.identity_)) {
        map.erase(it);
      }
    }
    if (map.empty()) {
      vec_it = maps.erase(vec_it);
    } else {
      ++vec_it;
    }
  }
}

void HostMapBuilder::remove(const absl::flat_hash_set<uint64_t>& removed_nids) {
  prunePolicyMapVec(ipv4_to_policy_, removed_nids);
  prunePolicyMapVec(ipv6_to_policy_, removed_nids);
}

void HostMap::logmaps(const std::string& msg) const {
  if (!ENVOY_LOG_CHECK_LEVEL(debug)) {
    return;
  }
  char buf[INET6_ADDRSTRLEN];
  std::string ip4, ip6;
  bool first = true;
  for (const auto& mask : ipv4_to_policy_) {
    std::string prefix = fmt::format("{}", mask.first);
    for (const auto& pair : mask.second) {
      if (!first) {
        ip4 += ", ";
      }
      first = false;
      ip4 += fmt::format("{}/{}->{}", inet_ntop(AF_INET, &pair.first, buf, sizeof(buf)), prefix,
                         pair.second.identity_);
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
      ip6 += fmt::format("{}/{}->{}", inet_ntop(AF_INET6, &pair.first, buf, sizeof(buf)), prefix,
                         pair.second.identity_);
    }
  }
  ENVOY_LOG(debug, "HostMap::{}: IPv4: [{}], IPv6: [{}]", msg, ip4, ip6);
}

const PolicyInfo& HostMap::resolve(uint32_t addr4) const {
  for (const auto& pair : ipv4_to_policy_) {
    auto it = pair.second.find(masked(addr4, pair.first));
    if (it != pair.second.end()) {
      return it->second;
    }
  }
  return unknownPolicyInfo();
}

const PolicyInfo& HostMap::resolve(absl::uint128 addr6) const {
  for (const auto& pair : ipv6_to_policy_) {
    auto it = pair.second.find(masked(addr6, pair.first));
    if (it != pair.second.end()) {
      return it->second;
    }
  }
  return unknownPolicyInfo();
}

const PolicyInfo& HostMap::resolve(const Network::Address::Ip* addr) const {
  auto* ipv4 = addr->ipv4();
  if (ipv4) {
    return resolve(ipv4->address());
  }
  auto* ipv6 = addr->ipv6();
  if (ipv6) {
    return resolve(ipv6->address());
  }
  return worldPolicyInfo();
}

} // namespace Cilium
} // namespace Envoy
