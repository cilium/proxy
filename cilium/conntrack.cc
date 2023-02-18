#include "conntrack.h"

#include <arpa/inet.h>
#include <string.h>

#include <cstdint>

#include "envoy/common/platform.h"

#include "source/common/common/utility.h"
#include "source/common/network/address_impl.h"

#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

// These must be kept in sync with Cilium source code, should refactor
// them to a separate include file we can include here instead of
// copying them!

typedef uint64_t __u64;
typedef uint32_t __be32; // Beware of the byte order!
typedef uint32_t __u32;
typedef uint16_t __be16; // Beware of the byte order!
typedef uint16_t __u16;
typedef uint8_t __u8;

#define TUPLE_F_OUT 0
#define TUPLE_F_IN 1

PACKED_STRUCT(struct ipv6_ct_tuple {
  __be32 saddr[4];
  __be32 daddr[4];
  __be16 dport;
  __be16 sport;
  __u8 nexthdr;
  __u8 flags;
});

PACKED_STRUCT(struct ipv4_ct_tuple {
  __be32 saddr;
  __be32 daddr;
  __be16 dport;
  __be16 sport;
  __u8 nexthdr;
  __u8 flags;
});

struct ct_entry {
  __u64 rx_packets;
  __u64 rx_bytes;
  __u64 tx_packets;
  __u64 tx_bytes;
  __u32 lifetime;
  __u16 rx_closing : 1, tx_closing : 1, nat46 : 1, lb_loopback : 1, seen_non_syn : 1, reserve : 11;
  __u16 rev_nat_index;
  __u16 slave;

  /* *x_flags_seen represents the OR of all TCP flags seen for the
   * transmit/receive direction of this entry. */
  __u8 tx_flags_seen;
  __u8 rx_flags_seen;

  __u32 src_sec_id; /* Used from userspace proxies, do not change offset! */

  /* last_*x_report is a timestamp of the last time a monitor
   * notification was sent for the transmit/receive direction. */
  __u32 last_tx_report;
  __u32 last_rx_report;
};

CtMap::CtMap4::CtMap4()
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct ipv4_ct_tuple), sizeof(struct ct_entry)) {}

CtMap::CtMap6::CtMap6()
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct ipv6_ct_tuple), sizeof(struct ct_entry)) {}

CtMap::CtMaps4::CtMaps4(const std::string& bpf_root, const std::string& map_name) : ok_(false) {
  // Open the IPv4 bpf maps from Cilium specific paths

  std::string path4tcp(bpf_root + "/tc/globals/cilium_ct4_" + map_name);
  if (!ctmap4_tcp_.open(path4tcp)) {
    ENVOY_LOG(warn, "cilium.bpf_metadata: Cannot open IPv4 conntrack map at {}", path4tcp);
    return;
  }
  std::string path4any(bpf_root + "/tc/globals/cilium_ct_any4_" + map_name);
  if (!ctmap4_any_.open(path4any)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open IPv4 conntrack map at {}", path4any);
    // do not fail if non-TCP map can not be opened
  }

  ok_ = true;
}

CtMap::CtMaps6::CtMaps6(const std::string& bpf_root, const std::string& map_name) : ok_(false) {
  // Open the IPv6 bpf maps from Cilium specific paths

  std::string path6tcp(bpf_root + "/tc/globals/cilium_ct6_" + map_name);
  if (!ctmap6_tcp_.open(path6tcp)) {
    ENVOY_LOG(warn, "cilium.bpf_metadata: Cannot open IPv6 conntrack map at {}", path6tcp);
    return;
  }
  std::string path6any(bpf_root + "/tc/globals/cilium_ct_any6_" + map_name);
  if (!ctmap6_any_.open(path6any)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open IPv6 conntrack map at {}", path6any);
    // do not fail if non-TCP map can not be opened
  }

  ok_ = true;
}

// Must hold mutex!
absl::flat_hash_map<const std::string, std::unique_ptr<CtMap::CtMaps4>>::iterator
CtMap::openMap4(const std::string& map_name) {
  auto pair = ct_maps4_.emplace(std::make_pair(map_name, nullptr));
  // construct the maps only if the entry was inserted
  if (pair.second) {
    auto maps = new CtMaps4(bpf_root_, map_name);
    if (!maps->ok_) {
      // Map open failed, delete and return nullptr
      delete maps;
      ct_maps4_.erase(pair.first);
      return ct_maps4_.end();
    }
    pair.first->second.reset(maps);
  }
  ENVOY_LOG(debug, "cilium.bpf_metadata: Opened IPv4 conntrack map {}", map_name);
  return pair.first;
}

// Must hold mutex!
absl::flat_hash_map<const std::string, std::unique_ptr<CtMap::CtMaps6>>::iterator
CtMap::openMap6(const std::string& map_name) {
  auto pair = ct_maps6_.emplace(std::make_pair(map_name, nullptr));
  // construct the maps only if the entry was inserted
  if (pair.second) {
    auto maps = new CtMaps6(bpf_root_, map_name);
    if (!maps->ok_) {
      // Map open failed, delete and return nullptr
      delete maps;
      ct_maps6_.erase(pair.first);
      return ct_maps6_.end();
    }
    pair.first->second.reset(maps);
  }
  ENVOY_LOG(debug, "cilium.bpf_metadata: Opened IPv6 conntrack map {}", map_name);
  return pair.first;
}

void CtMap::closeMaps(const std::shared_ptr<absl::flat_hash_set<std::string>>& to_be_closed) {
  std::lock_guard<std::mutex> guard(maps_mutex_);

  for (const auto& name : *to_be_closed) {
    auto ct4 = ct_maps4_.find(name);
    if (ct4 != ct_maps4_.end()) {
      ct_maps4_.erase(ct4);
      ENVOY_LOG(debug, "cilium.bpf_metadata: Closed IPv4 conntrack map {}", name);
    }
    auto ct6 = ct_maps6_.find(name);
    if (ct6 != ct_maps6_.end()) {
      ct_maps6_.erase(ct6);
      ENVOY_LOG(debug, "cilium.bpf_metadata: Closed IPv6 conntrack map {}", name);
    }
  }
}

CtMap::CtMap(const std::string& bpf_root) : bpf_root_(bpf_root) {
  if (openMap4("global") == ct_maps4_.end() && openMap6("global") == ct_maps6_.end()) {
    ENVOY_LOG(debug, "cilium.bpf_metadata: conntrack map global open failed: ({})",
              Envoy::errorDetails(errno));
  }
}

// map_name is "global" for the global maps, or endpoint ID for local maps
uint32_t CtMap::lookupSrcIdentity(const std::string& map_name, const Network::Address::Ip* sip,
                                  const Network::Address::Ip* dip, bool ingress) {
  ENVOY_LOG(debug, "cilium.bpf_metadata: Using conntrack map {}", map_name);

  struct ipv4_ct_tuple key4 {};
  struct ipv6_ct_tuple key6 {};
  struct ct_entry value {};

  if (sip->version() == Network::Address::IpVersion::v4 &&
      dip->version() == Network::Address::IpVersion::v4) {
    key4.daddr = dip->ipv4()->address();
    key4.saddr = sip->ipv4()->address();
    key4.sport = htons(sip->port());
    key4.dport = htons(dip->port());
    key4.nexthdr = 6;                                // TCP only for now
    key4.flags = ingress ? TUPLE_F_IN : TUPLE_F_OUT; // also reversed

    ENVOY_LOG(trace,
              "cilium.bpf_metadata: Looking up key: {:x}, {:x}, {:x}, {:x}, "
              "{:x}, {:x}",
              ntohl(key4.daddr), ntohl(key4.saddr), ntohs(key4.dport), ntohs(key4.sport),
              key4.nexthdr, key4.flags);
  } else if (sip->version() == Network::Address::IpVersion::v6 &&
             dip->version() == Network::Address::IpVersion::v6) {
    absl::uint128 daddr = dip->ipv6()->address();
    absl::uint128 saddr = sip->ipv6()->address();
    memcpy(&key6.daddr, &daddr, 16); // NOLINT(safe-memcpy)
    memcpy(&key6.saddr, &saddr, 16); // NOLINT(safe-memcpy)
    key6.sport = htons(sip->port());
    key6.dport = htons(dip->port());
    key6.nexthdr = 6; // TCP only for now
    key6.flags = ingress ? TUPLE_F_IN : TUPLE_F_OUT;
  } else {
    ENVOY_LOG(info, "cilium.bpf_metadata: Address type mismatch: Source: {}, Dest: {}",
              sip->addressAsString(), dip->addressAsString());
    return 0;
  }

  if (dip->version() == Network::Address::IpVersion::v4) {
    // Lock for the duration of the map lookup and conntrack lookup
    std::lock_guard<std::mutex> guard(maps_mutex_);
    auto it = ct_maps4_.find(map_name);
    if (it == ct_maps4_.end()) {
      it = openMap4(map_name);
    }
    if (it == ct_maps4_.end()) {
      ENVOY_LOG(error, "cilium.bpf_metadata: No IPv4 conntrack map {}", map_name);
      return 0;
    }
    auto ct = it->second.get();
    if (!ct->ctmap4_tcp_.lookup(&key4, &value)) {
      ct_maps4_.erase(it); // flush the map to force reload after each failure.
      ENVOY_LOG(info, "cilium.bpf_metadata: IPv4 conntrack map {} lookup failed: {}", map_name,
                Envoy::errorDetails(errno));
      return 0;
    }
  } else {
    // Lock for the duration of the map lookup and conntrack lookup
    std::lock_guard<std::mutex> guard(maps_mutex_);
    auto it = ct_maps6_.find(map_name);
    if (it == ct_maps6_.end()) {
      it = openMap6(map_name);
    }
    if (it == ct_maps6_.end()) {
      ENVOY_LOG(error, "cilium.bpf_metadata: No IPv6 conntrack map {}", map_name);
      return 0;
    }
    auto ct = it->second.get();
    if (!ct->ctmap6_tcp_.lookup(&key6, &value)) {
      ct_maps6_.erase(it); // flush the map to force reload after each failure.
      ENVOY_LOG(info, "cilium.bpf_metadata: IPv6 conntrack map {} lookup failed: {}", map_name,
                Envoy::errorDetails(errno));
      return 0;
    }
  }
  return value.src_sec_id;
}

} // namespace Cilium
} // namespace Envoy
