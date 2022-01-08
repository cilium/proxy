#pragma once

#include "bpf.h"
#include "source/common/common/logger.h"
#include "envoy/network/address.h"
#include "envoy/singleton/instance.h"

namespace Envoy {
namespace Cilium {

class IPCache : public Singleton::Instance, public Bpf {
 public:
  IPCache(const std::string& bpf_root);
  bool Open();

  const std::string& bpfRoot() { return bpf_root_; }

  uint32_t resolve(const Network::Address::Ip* ip);

 private:
  std::string bpf_root_;
};

typedef std::shared_ptr<IPCache> IPCacheSharedPtr;

}  // namespace Cilium
}  // namespace Envoy
