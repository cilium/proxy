#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"

#include "source/common/common/thread.h"

#include "cilium/bpf.h"

namespace Envoy {
namespace Cilium {

class IPCache : public Singleton::Instance, public Bpf {
public:
  static std::shared_ptr<IPCache> NewIPCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& path);
  static std::shared_ptr<IPCache> GetIPCache(Server::Configuration::ServerFactoryContext& context);

  IPCache(const std::string& path);
  void SetPath(const std::string& path);
  bool Open();
  bool open_locked();

  uint32_t resolve(const Network::Address::Ip* ip);

private:
  Thread::MutexBasicLockable path_mutex_;
  std::string path_;
};

typedef std::shared_ptr<IPCache> IPCacheSharedPtr;

} // namespace Cilium
} // namespace Envoy
