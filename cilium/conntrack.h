#pragma once

#include <functional>
#include <memory>
#include <string>

#include "envoy/network/address.h"
#include "envoy/singleton/instance.h"

#include "source/common/common/logger.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "bpf.h"

namespace std {
template <> class hash<const string> {
public:
  size_t operator()(const string& key) const { return hash<string>()(key); }
};
}; // namespace std

namespace Envoy {
namespace Cilium {

class CtMap : public Singleton::Instance, Logger::Loggable<Logger::Id::filter> {
public:
  CtMap(const std::string& bpf_root);

  const std::string& bpfRoot() { return bpf_root_; }

  uint32_t lookupSrcIdentity(const std::string& map_name, const Network::Address::Ip* sip,
                             const Network::Address::Ip* dip, bool ingress);

private:
  class CtMap4 : public Bpf {
  public:
    CtMap4();
  };

  class CtMap6 : public Bpf {
  public:
    CtMap6();
  };

public:
  class CtMaps4 {
  public:
    CtMaps4(const std::string& bpf_root, const std::string& map_name);

    bool ok_;
    CtMap4 ctmap4_tcp_;
    CtMap4 ctmap4_any_;
  };
  class CtMaps6 {
  public:
    CtMaps6(const std::string& bpf_root, const std::string& map_name);

    bool ok_;
    CtMap6 ctmap6_tcp_;
    CtMap6 ctmap6_any_;
  };
  void closeMaps(const std::shared_ptr<absl::flat_hash_set<std::string>>& to_be_closed);

private:
  absl::flat_hash_map<const std::string, std::unique_ptr<CtMaps4>>::iterator
  openMap4(const std::string& map_name);
  absl::flat_hash_map<const std::string, std::unique_ptr<CtMaps6>>::iterator
  openMap6(const std::string& map_name);

  // All known conntrack maps. Populated with the "global" maps at startup,
  // further maps are opened and inserted on demand.
  std::mutex maps_mutex_;
  absl::flat_hash_map<const std::string, std::unique_ptr<CtMaps4>> ct_maps4_;
  absl::flat_hash_map<const std::string, std::unique_ptr<CtMaps6>> ct_maps6_;
  std::string bpf_root_;
};

typedef std::shared_ptr<CtMap> CtMapSharedPtr;

} // namespace Cilium
} // namespace Envoy
