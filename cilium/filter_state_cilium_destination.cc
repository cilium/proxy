#include "cilium/filter_state_cilium_destination.h"

#include <string>

#include "source/common/common/macros.h"

namespace Envoy {
namespace Cilium {

const std::string& CiliumDestinationFilterState::key() {
  CONSTRUCT_ON_FIRST_USE(std::string, "cilium.destination.address");
}

} // namespace Cilium
} // namespace Envoy
