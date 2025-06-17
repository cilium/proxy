#include "ipcache.h"

#include <cerrno> // IWYU pragma: keep
#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/manager.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "absl/numeric/int128.h"
#include "absl/synchronization/mutex.h"
#include "cilium/bpf.h"
#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

bool operator==(const IpCacheKey& a, const IpCacheKey& b) { return memcmp(&a, &b, sizeof(a)) == 0; }

template <typename H> H AbslHashValue(H state, const IpCacheKey& key) {
  // Combine the hash of each member into the state
  H h = H::combine_contiguous(std::move(state), reinterpret_cast<const char*>(&key), sizeof(key));
  return h;
}

SINGLETON_MANAGER_REGISTRATION(cilium_ipcache);

IpCacheSharedPtr IpCache::newIpCache(Server::Configuration::ServerFactoryContext& context,
                                     const std::string& path,
                                     std::chrono::milliseconds cache_gc_interval) {
  auto ipcache = context.singletonManager().getTyped<Cilium::IpCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_ipcache), [&path, &context, &cache_gc_interval] {
        auto ipcache = std::make_shared<Cilium::IpCache>(context, path, cache_gc_interval);
        if (!ipcache->open()) {
          ipcache.reset();
        }
        return ipcache;
      });

  // Override the current path even on an existing singleton
  if (ipcache) {
    ipcache->setConfig(path, cache_gc_interval);
  }
  return ipcache;
}

IpCacheSharedPtr IpCache::getIpCache(Server::Configuration::ServerFactoryContext& context) {
  return context.singletonManager().getTyped<Cilium::IpCache>(
      SINGLETON_MANAGER_REGISTERED_NAME(cilium_ipcache));
}

IpCache::IpCache(Server::Configuration::ServerFactoryContext& context, const std::string& path,
                 std::chrono::milliseconds cache_gc_interval)
    : Bpf(BPF_MAP_TYPE_LPM_TRIE, sizeof(struct IpCacheKey), sizeof(SecLabelType),
          sizeof(struct RemoteEndpointInfo)),
      dispatcher_(context.mainThreadDispatcher()),
      cache_gc_timer_(dispatcher_.createTimer([this]() { cacheGc(); })),
      cache_gc_interval_(cache_gc_interval), time_source_(context.timeSource()), path_(path) {
  // Timer for cache GC
  if (cache_gc_interval_ != std::chrono::milliseconds(0)) {
    cache_gc_timer_->enableTimer(cache_gc_interval_);
  }
}

void IpCache::cacheGc() {
  {
    absl::WriterMutexLock lock(&mutex_);
    for (auto it = cache_.begin(); it != cache_.end(); it++) {
      auto age = time_source_.monotonicTime() - it->second.time_stamp;
      if (age >= std::chrono::milliseconds(1)) {
        ENVOY_LOG(trace, "cilium.ipcache: local cache GC deleting old entry {}:{}",
                  it->first.asString(), it->second.sec_label);
        cache_.erase(it);
      }
    }
  }
  cache_gc_timer_->enableTimer(cache_gc_interval_);
}

void IpCache::setConfig(const std::string& path, std::chrono::milliseconds cache_gc_interval) {
  absl::WriterMutexLock lock(&mutex_);
  // update GC interval?
  if (cache_gc_interval != cache_gc_interval_) {
    cache_gc_timer_->disableTimer();
    cache_gc_interval_ = cache_gc_interval;
    if (cache_gc_interval_ != std::chrono::milliseconds(0)) {
      cache_gc_timer_->enableTimer(cache_gc_interval_);
    }
  }
  // re-open on path change
  if (path != path_) {
    path_ = path;
    openLocked();
  }
}

bool IpCache::open() {
  absl::WriterMutexLock lock(&mutex_);
  return openLocked();
}

bool IpCache::openLocked() {
  if (Bpf::open(path_)) {
    ENVOY_LOG(debug, "cilium.ipcache: Opened ipcache at {}", path_);
    return true;
  }
  ENVOY_LOG(warn, "cilium.ipcache: Cannot open ipcache at {}", path_);
  return false;
}

uint32_t IpCache::resolve(const Network::Address::Ip* ip, std::chrono::microseconds cache_ttl) {
  struct IpCacheKey key {};
  struct RemoteEndpointInfo value {};

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

  bool ok;
  bool use_cache = cache_ttl > std::chrono::microseconds(0);
  {
    // Read lock prevents ipcache lookups while ipcache is being reopened.
    absl::ReaderMutexLock lock(&mutex_);

    // local cache lookup
    if (use_cache) {
      const auto it = cache_.find(key);
      if (it != cache_.cend()) {
        auto age = time_source_.monotonicTime() - it->second.time_stamp;
        if (age < cache_ttl) {
          // use cached value
          ENVOY_LOG(trace, "cilium.ipcache: {} has cached ID {}", ip->addressAsString(),
                    it->second.sec_label);
          return it->second.sec_label;
        }
      }
    }

    ENVOY_LOG(trace, "cilium.ipcache: Looking up key: {}", key.asString());
    ok = lookup(&key, &value);
  }

  if (ok) {
    ENVOY_LOG(debug, "cilium.ipcache: {} has ID {}", ip->addressAsString(), value.sec_label);

    // cache result
    if (use_cache) {
      absl::WriterMutexLock lock(&mutex_);
      cache_.insert_or_assign(key,
                              CachedEndpointInfo{value.sec_label, time_source_.monotonicTime()});
    }
    return value.sec_label;
  }
  ENVOY_LOG(info, "cilium.ipcache: bpf map lookup failed: {}", Envoy::errorDetails(errno));
  return 0;
}

} // namespace Cilium
} // namespace Envoy
