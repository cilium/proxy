#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "envoy/network/address.h"

#include "source/common/common/logger.h"
#include "source/common/protobuf/protobuf.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/numeric/int128.h"

namespace Envoy {
namespace Cilium {

struct NamedPort {
  uint16_t port_;
  std::string name_;

  bool operator==(const NamedPort& other) const {
    return port_ == other.port_ && name_ == other.name_;
  }
};

using NamedPorts = std::vector<NamedPort>;

struct PolicyInfo {
  uint64_t identity_;
  // Shared by all addresses of this identity; sorted by name and port, with no duplicates.
  std::shared_ptr<const NamedPorts> named_ports_;
};

// An address-to-identity and named-port index shared as an immutable snapshot by its owner.
class HostMap : public Logger::Loggable<Logger::Id::config> {
public:
  void logmaps(const std::string& msg) const;

  // Return the longest prefix match, or UNKNOWN when no address entry matches.
  uint64_t resolve(uint32_t addr4) const;
  uint64_t resolve(absl::uint128 addr6) const;
  uint64_t resolve(const Network::Address::Ip* addr) const;

private:
  friend class HostMapBuilder;

  // Prefix lengths are ordered from longest to shortest. Keys contain network-order addresses
  // with all bits outside the prefix cleared.
  std::vector<std::pair<unsigned int, absl::flat_hash_map<uint32_t, PolicyInfo>>> ipv4_to_policy_;
  std::vector<std::pair<unsigned int, absl::flat_hash_map<absl::uint128, PolicyInfo>>>
      ipv6_to_policy_;
};

// Only mutate an unpublished candidate on the main thread. A failed candidate is discarded;
// after validation its HostMap base can be moved into an immutable published snapshot.
class HostMapBuilder : public HostMap {
public:
  HostMapBuilder() = default;
  explicit HostMapBuilder(const HostMap* host_map);

  void insert(uint64_t identity, const Protobuf::RepeatedPtrField<std::string>& addresses,
              NamedPorts named_ports = {});
  void remove(const absl::flat_hash_set<uint64_t>& identities);

private:
  template <typename M> M& getMap(std::vector<std::pair<unsigned int, M>>& maps, unsigned int plen);

  template <typename MapVec>
  void prunePolicyMapVec(MapVec& maps, const absl::flat_hash_set<uint64_t>& identities);
};

} // namespace Cilium
} // namespace Envoy
