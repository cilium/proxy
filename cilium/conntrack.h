#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/singleton/instance.h"

#include "source/common/common/logger.h"

#include "cilium/bpf.h"

namespace Envoy {
namespace Cilium {

class CtMap : public Singleton::Instance, Logger::Loggable<Logger::Id::filter> {
public:
  CtMap(const std::string& bpf_root);

  const std::string& bpfRoot() { return bpf_root_; }

  uint32_t lookupSrcIdentity(const Network::Address::Ip* sip, const Network::Address::Ip* dip,
                             bool ingress);

private:
  class CtMap4 : public Bpf {
  public:
    CtMap4(const std::string& bpf_root);

    bool open();

  private:
    std::string path_;
  };

  class CtMap6 : public Bpf {
  public:
    CtMap6(const std::string& bpf_root);

    bool open();

  private:
    std::string path_;
  };

public:
  std::string bpf_root_;
  CtMap4 ct_map4_;
  CtMap6 ct_map6_;
};

using CtMapSharedPtr = std::shared_ptr<CtMap>;

} // namespace Cilium
} // namespace Envoy
