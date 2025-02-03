#include "ipcache.h"

#include <netinet/in.h>

#include <cerrno> // IWYU pragma: keep
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "envoy/common/platform.h"
#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/manager.h"

#include "source/common/common/lock_guard.h"
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

typedef uint32_t __be32; // Beware of the byte order!
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
  using SecLabelType = __u32;
  SecLabelType sec_label;
  char buf[60]; // Enough space for all fields after the 'sec_label'
};

#define ENDPOINT_KEY_IPV4 1
#define ENDPOINT_KEY_IPV6 2

SINGLETON_MANAGER_REGISTRATION(cilium_ipcache);

IPCacheSharedPtr IPCache::NewIPCache(Server::Configuration::ServerFactoryContext& context,
                                     const std::string& path) {
  auto ipcache = context.singletonManager().getTyped<Cilium::IPCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_ipcache), [&path] {
        auto ipcache = std::make_shared<Cilium::IPCache>(path);
        if (!ipcache->Open()) {
          ipcache.reset();
        }
        return ipcache;
      });

  // Override the current path even on an existing singleton
  if (ipcache) {
    ipcache->SetPath(path);
  }
  return ipcache;
}

IPCacheSharedPtr IPCache::GetIPCache(Server::Configuration::ServerFactoryContext& context) {
  return context.singletonManager().getTyped<Cilium::IPCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_ipcache));
}

IPCache::IPCache(const std::string& path)
    : Bpf(BPF_MAP_TYPE_LPM_TRIE, sizeof(struct ipcache_key),
          sizeof(remote_endpoint_info::SecLabelType), sizeof(struct remote_endpoint_info)),
      path_(path) {}

void IPCache::SetPath(const std::string& path) {
  Thread::LockGuard guard(path_mutex_);
  if (path != path_) {
    path_ = path;
    // re-open on path change
    open_locked();
  }
}

bool IPCache::Open() {
  Thread::LockGuard guard(path_mutex_);
  return open_locked();
}

bool IPCache::open_locked() {
  if (Bpf::open(path_)) {
    ENVOY_LOG(debug, "cilium.ipcache: Opened ipcache at {}", path_);
    return true;
  }
  ENVOY_LOG(warn, "cilium.ipcache: Cannot open ipcache at {}", path_);
  return false;
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
    memcpy(&key.ip6, &ip6, sizeof key.ip6); // NOLINT(safe-memcpy)
  }

  if (key.family == ENDPOINT_KEY_IPV4) {
    ENVOY_LOG(trace, "cilium.ipcache: Looking up key: {:x}, prefixlen: {}", ntohl(key.ip4),
              key.lpm_key.prefixlen - 32);
  } else if (key.family == ENDPOINT_KEY_IPV6) {
    ENVOY_LOG(trace, "cilium.ipcache: Looking up key: {:x}:{:x}:{:x}:{:x}, prefixlen {}",
              ntohl(key.ip6[0]), ntohl(key.ip6[1]), ntohl(key.ip6[2]), ntohl(key.ip6[3]),
              key.lpm_key.prefixlen - 32);
  }

  if (lookup(&key, &value)) {
    ENVOY_LOG(debug, "cilium.ipcache: {} has ID {}", ip->addressAsString(), value.sec_label);
    return value.sec_label;
  }
  ENVOY_LOG(info, "cilium.ipcache: bpf map lookup failed: {}", Envoy::errorDetails(errno));
  return 0;
}

} // namespace Cilium
} // namespace Envoy
