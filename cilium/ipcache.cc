#include "ipcache.h"

#include <arpa/inet.h>

#include "common/common/utility.h"
#include "envoy/common/platform.h"
#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

// These must be kept in sync with Cilium source code, should refactor
// them to a separate include file we can include here instead of
// copying them!

typedef uint32_t __be32;  // Beware of the byte order!
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;

PACKED_STRUCT(struct ipcache_key {
  struct bpf_lpm_trie_key lpm_key;
  __u16 pad1;
  __u8 pad2;
  __u8 family;
  union {
    struct {
      __u32 ip4;
      __u32 pad4;
      __u32 pad5;
      __u32 pad6;
    };
    __u32 ip6[4];
  };
});

struct remote_endpoint_info {
  __u32 sec_label;
  __u32 tunnel_endpoint;
  __u8 key;
};

#define ENDPOINT_KEY_IPV4 1
#define ENDPOINT_KEY_IPV6 2

IPCache::IPCache(const std::string& bpf_root)
    : Bpf(BPF_MAP_TYPE_LPM_TRIE, sizeof(struct ipcache_key),
          sizeof(struct remote_endpoint_info)),
      bpf_root_(bpf_root) {}

bool IPCache::Open() {
  // Open the bpf maps from Cilium specific paths
  std::string path(bpf_root_ + "/tc/globals/cilium_ipcache");
  if (!open(path)) {
    ENVOY_LOG(info, "cilium.ipcache: Cannot open ipcache map at {}", path);
    return false;
  }
  ENVOY_LOG(debug, "cilium.ipcache: Opened ipcache.");
  return true;
}

uint32_t IPCache::resolve(const Network::Address::Ip* ip) {
  struct ipcache_key key {};
  struct remote_endpoint_info value {};

  if (ip->version() == Network::Address::IpVersion::v4) {
    key.lpm_key = {32 + 32, {}};
    key.family = ENDPOINT_KEY_IPV4;
    key.ip4 = ip->ipv4()->address();
  } else {
    key.lpm_key = {32 + 128, {}};
    key.family = ENDPOINT_KEY_IPV6;
    absl::uint128 ip6 = ip->ipv6()->address();
    memcpy(&key.ip6, &ip6, sizeof key.ip6);
  }

  if (key.family == ENDPOINT_KEY_IPV4) {
    ENVOY_LOG(trace, "cilium.ipcache: Looking up key: {:x}, prefixlen: {}",
              ntohl(key.ip4), key.lpm_key.prefixlen - 32);
  } else if (key.family == ENDPOINT_KEY_IPV6) {
    ENVOY_LOG(
        trace,
        "cilium.ipcache: Looking up key: {:x}:{:x}:{:x}:{:x}, prefixlen {}",
        ntohl(key.ip6[0]), ntohl(key.ip6[1]), ntohl(key.ip6[2]),
        ntohl(key.ip6[3]), key.lpm_key.prefixlen - 32);
  }

  if (lookup(&key, &value)) {
    ENVOY_LOG(debug, "cilium.ipcache: {} has ID {}", ip->addressAsString(),
              value.sec_label);
    return value.sec_label;
  }
  ENVOY_LOG(info, "cilium.ipcache: bpf map lookup failed: {}",
            Envoy::errorDetails(errno));
  return 0;
}

}  // namespace Cilium
}  // namespace Envoy
