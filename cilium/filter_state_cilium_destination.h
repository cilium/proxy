#pragma once

#include <string>
#include <utility>

#include "envoy/network/address.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Cilium {

class CiliumDestinationFilterState : public StreamInfo::FilterState::Object,
                                     public Logger::Loggable<Logger::Id::filter> {
public:
  explicit CiliumDestinationFilterState(Network::Address::InstanceConstSharedPtr dst_address)
      : dst_address_(std::move(dst_address)) {};

  void setDestinationAddress(const Network::Address::InstanceConstSharedPtr& address) {
    dst_address_ = address;
  }

  Network::Address::InstanceConstSharedPtr getDestinationAddress() const { return dst_address_; }
  static const std::string& key();

  Network::Address::InstanceConstSharedPtr dst_address_;
};
} // namespace Cilium
} // namespace Envoy
