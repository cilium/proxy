#pragma once

#include "envoy/network/address.h"
#include "envoy/server/factory_context.h"
#include "envoy/singleton/instance.h"

#include "source/common/common/logger.h"

#include "bpf.h"

namespace Envoy {
namespace Cilium {

class IPCache : public Singleton::Instance, public Bpf {
public:
  static std::shared_ptr<IPCache> NewIPCache(Server::Configuration::ServerFactoryContext& context,
                                             const std::string& bpf_root);
  static std::shared_ptr<IPCache> GetIPCache(Server::Configuration::ServerFactoryContext& context);

  IPCache(const std::string& bpf_root);
  bool Open();

  const std::string& bpfRoot() { return bpf_root_; }

  uint32_t resolve(const Network::Address::Ip* ip);

private:
  std::string bpf_root_;
};

typedef std::shared_ptr<IPCache> IPCacheSharedPtr;

} // namespace Cilium
} // namespace Envoy
