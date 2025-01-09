#pragma once

#include <asm-generic/socket.h>
#include <netinet/in.h>

#include <cerrno>
#include <cstdint>
#include <vector>

#include "envoy/config/core/v3/socket_option.pb.h"
#include "envoy/network/socket.h"

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "absl/types/optional.h"

namespace Envoy {
namespace Cilium {

// Socket Option that programmatically sets the socket option SO_REUSEADDR on the socket.
class ReuseAddrSocketOption : public Network::Socket::Option,
                              public Logger::Loggable<Logger::Id::filter> {
public:
  ReuseAddrSocketOption() { ENVOY_LOG(debug, "Cilium ReuseAddrSocketOption()"); }

  absl::optional<Network::Socket::Option::Details>
  getOptionDetails(const Network::Socket&,
                   envoy::config::core::v3::SocketOption::SocketState) const override {
    return absl::nullopt;
  }

  bool setOption(Network::Socket& socket,
                 envoy::config::core::v3::SocketOption::SocketState state) const override {
    // Only set the option once per socket
    if (state != envoy::config::core::v3::SocketOption::STATE_PREBIND) {
      ENVOY_LOG(trace, "Skipping setting socket ({}) option SO_REUSEADDR, state != STATE_PREBIND",
                socket.ioHandle().fdDoNotUse());
      return true;
    }

    uint32_t one = 1;

    // Allow reuse of the original source address. This may by needed for
    // retries to not fail on "address already in use" when using a specific
    // source address and port.
    {
      auto status = socket.setSocketOption(SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
      if (status.return_value_ < 0) {
        ENVOY_LOG(critical, "Failed to set socket option SO_REUSEADDR: {}",
                  Envoy::errorDetails(status.errno_));
        return false;
      }
    }

    ENVOY_LOG(trace, "Successfully set socket option SO_REUSEADDR on socket: {}",
              socket.ioHandle().fdDoNotUse());

    return true;
  }

  void hashKey([[maybe_unused]] std::vector<uint8_t>& key) const override {}

  bool isSupported() const override { return true; }
};

} // namespace Cilium
} // namespace Envoy
