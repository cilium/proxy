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
  static std::shared_ptr<IPCache> newIpCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& path);
  static std::shared_ptr<IPCache> getIpCache(Server::Configuration::ServerFactoryContext& context);

  IPCache(const std::string& path);
  void setPath(const std::string& path);
  bool open();
  bool openLocked();

  uint32_t resolve(const Network::Address::Ip* ip);

private:
  Thread::MutexBasicLockable path_mutex_;
  std::string path_;
};

using IPCacheSharedPtr = std::shared_ptr<IPCache>;

} // namespace Cilium
} // namespace Envoy
