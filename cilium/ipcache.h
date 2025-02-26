#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"

#include "cilium/bpf.h"

namespace Envoy {
namespace Cilium {

class IPCache : public Singleton::Instance, public Bpf {
public:
  static std::shared_ptr<IPCache> newIpCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& bpf_root);
  static std::shared_ptr<IPCache> getIpCache(Server::Configuration::ServerFactoryContext& context);

  IPCache(const std::string& bpf_root);
  bool open();

  const std::string& bpfRoot() { return bpf_root_; }

  uint32_t resolve(const Network::Address::Ip* ip);

private:
  std::string bpf_root_;
};

using IPCacheSharedPtr = std::shared_ptr<IPCache>;

} // namespace Cilium
} // namespace Envoy
