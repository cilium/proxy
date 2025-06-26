#pragma once

#include <netinet/in.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

#include "envoy/common/platform.h"
#include "envoy/common/time.h"
#include "envoy/event/timer.h"
#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"
#include "cilium/bpf.h"
#include "linux/bpf.h"
#include "linux/type_mapper.h"

namespace Envoy {
namespace Cilium {

// These must be kept in sync with Cilium source code, should refactor
// them to a separate include file we can include here instead of
// copying them!

using __be32 = uint32_t; // Beware of the byte order!
using __u64 = uint64_t;
using __u32 = uint32_t;
using __u16 = uint16_t;
using __u8 = uint8_t;

#define ENDPOINT_KEY_IPV4 1
#define ENDPOINT_KEY_IPV6 2

PACKED_STRUCT(struct IpCacheKey {
  std::string asString() const {
    if (family == ENDPOINT_KEY_IPV4) {
      auto ip = ntohl(ip4);
      return fmt::format("{}.{}.{}.{}/{}", uint8_t(ip >> 24), uint8_t(ip >> 16), uint8_t(ip >> 8),
                         uint8_t(ip), lpm_key.prefixlen - 32);
    } else if (family == ENDPOINT_KEY_IPV6) {
      return fmt::format("{:x}:{:x}:{:x}:{:x}/{}", ntohl(ip6[0]), ntohl(ip6[1]), ntohl(ip6[2]),
                         ntohl(ip6[3]), lpm_key.prefixlen - 32);
    }
    return "invalid ipcache key";
  }

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

bool operator==(const IpCacheKey& a, const IpCacheKey& b);

template <typename H> H AbslHashValue(H state, const IpCacheKey& key);

using SecLabelType = __u32;

struct RemoteEndpointInfo {
  SecLabelType sec_label;
  char buf[60]; // Enough space for all fields after the 'sec_label'
};

struct CachedEndpointInfo {
  SecLabelType sec_label;
  MonotonicTime time_stamp;
};

using IpCacheMap = absl::flat_hash_map<struct IpCacheKey, struct CachedEndpointInfo>;

class IpCache : public Singleton::Instance, public Bpf {
public:
  static std::shared_ptr<IpCache> newIpCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& path,
                                             std::chrono::milliseconds cache_gc_interval);
  static std::shared_ptr<IpCache> getIpCache(Server::Configuration::ServerFactoryContext& context);

  IpCache(Server::Configuration::ServerFactoryContext& context, const std::string& path,
          std::chrono::milliseconds cache_gc_interval);

  void setConfig(const std::string& path, std::chrono::milliseconds cache_gc_interval)
      ABSL_LOCKS_EXCLUDED(mutex_);
  bool open() ABSL_LOCKS_EXCLUDED(mutex_);

  uint32_t resolve(const Network::Address::Ip* ip, std::chrono::microseconds cache_ttl)
      ABSL_LOCKS_EXCLUDED(mutex_);

private:
  bool openLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_);
  void cacheGc() ABSL_LOCKS_EXCLUDED(mutex_);

  Event::Dispatcher& dispatcher_;
  Event::TimerPtr cache_gc_timer_;
  std::chrono::milliseconds cache_gc_interval_;
  TimeSource& time_source_;

  absl::Mutex mutex_;
  std::string path_;
  IpCacheMap cache_;
};

using IpCacheSharedPtr = std::shared_ptr<IpCache>;

} // namespace Cilium
} // namespace Envoy
