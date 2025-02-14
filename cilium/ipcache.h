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

class IpCache : public Singleton::Instance, public Bpf {
public:
  static std::shared_ptr<IpCache> newIpCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& path);
  static std::shared_ptr<IpCache> getIpCache(Server::Configuration::ServerFactoryContext& context);

  IpCache(const std::string& path);
  void setPath(const std::string& path);
  bool open();
  bool openLocked();

  uint32_t resolve(const Network::Address::Ip* ip);

private:
  Thread::MutexBasicLockable path_mutex_;
  std::string path_;
};

using IpCacheSharedPtr = std::shared_ptr<IpCache>;

} // namespace Cilium
} // namespace Envoy
