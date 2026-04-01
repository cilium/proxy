#include "conntrack.h"

#include <netinet/in.h>

#include <cerrno> // IWYU pragma: keep
#include <cstdint>
#include <cstring>
#include <string>

#include "envoy/common/platform.h"
#include "envoy/network/address.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "absl/numeric/int128.h"
#include "cilium/bpf.h"
#include "linux/bpf.h"
#include "linux/type_mapper.h"

namespace Envoy {
namespace Cilium {

// These must be kept in sync with Cilium source code, should refactor
// them to a separate include file we can include here instead of
// copying them!

using __u64 = uint64_t;
using __be32 = uint32_t; // Beware of the byte order!
using __u32 = uint32_t;
using __be16 = uint16_t; // Beware of the byte order!
using __u16 = uint16_t;
using __u8 = uint8_t;

#define TUPLE_F_OUT 0
#define TUPLE_F_IN 1

PACKED_STRUCT(struct IPv6CtTuple {
  __be32 saddr[4];
  __be32 daddr[4];
  __be16 dport;
  __be16 sport;
  __u8 nexthdr;
  __u8 flags;
});

PACKED_STRUCT(struct IPv4CtTuple {
  __be32 saddr;
  __be32 daddr;
  __be16 dport;
  __be16 sport;
  __u8 nexthdr;
  __u8 flags;
});

struct CtEntry {
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

CtMap::CtMap4::CtMap4(const std::string& bpf_root)
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct IPv4CtTuple), sizeof(struct CtEntry)),
      path_(bpf_root + "/tc/globals/cilium_ct4_global") {}

bool CtMap::CtMap4::open() {
  bool ret = Bpf::open(path_);
  if (!ret) {
    ENVOY_LOG(warn, "cilium.bpf_metadata: Cannot open IPv4 conntrack map at {}", path_);
  }
  return ret;
}

CtMap::CtMap6::CtMap6(const std::string& bpf_root)
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct IPv6CtTuple), sizeof(struct CtEntry)),
      path_(bpf_root + "/tc/globals/cilium_ct6_global") {}

bool CtMap::CtMap6::open() {
  bool ret = Bpf::open(path_);
  if (!ret) {
    ENVOY_LOG(warn, "cilium.bpf_metadata: Cannot open IPv6 conntrack map at {}", path_);
  }
  return ret;
}

CtMap::CtMap(const std::string& bpf_root)
    : bpf_root_(bpf_root), ct_map4_(bpf_root), ct_map6_(bpf_root) {
  if (!ct_map4_.open() && !ct_map6_.open()) {
    ENVOY_LOG(debug, "cilium.bpf_metadata: conntrack map global open failed: ({})",
              Envoy::errorDetails(errno));
  }
}

// map_name is "global" for the global maps, or endpoint ID for local maps
uint32_t CtMap::lookupSrcIdentity(const Network::Address::Ip* sip, const Network::Address::Ip* dip,
                                  bool ingress) {
  ENVOY_LOG(debug, "cilium.bpf_metadata: Using conntrack map global");

  struct IPv4CtTuple key4 {};
  struct IPv6CtTuple key6 {};
  struct CtEntry value {};

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
    if (!ct_map4_.lookup(&key4, &value)) {
      ct_map4_.close(); // flush the map to force reload after each failure.
      ENVOY_LOG(debug, "cilium.bpf_metadata: IPv4 conntrack map lookup failed: {}",
                Envoy::errorDetails(errno));
      return 0;
    }
  } else {
    if (!ct_map6_.lookup(&key6, &value)) {
      ct_map6_.close(); // flush the map to force reload after each failure.
      ENVOY_LOG(debug, "cilium.bpf_metadata: IPv6 conntrack map lookup failed: {}",
                Envoy::errorDetails(errno));
      return 0;
    }
  }
  return value.src_sec_id;
}

} // namespace Cilium
} // namespace Envoy
