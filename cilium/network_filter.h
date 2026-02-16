#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/common/time.h"
#include "envoy/json/json_object.h"
#include "envoy/network/address.h"
#include "envoy/network/filter.h"
#include "envoy/server/factory_context.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "absl/strings/string_view.h"
#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/network_filter.pb.h"
#include "cilium/filter_state_cilium_destination.h"
#include "cilium/filter_state_cilium_policy.h"
#include "cilium/proxylib.h"

namespace Envoy {
namespace Filter {
namespace CiliumL3 {

/**
 * Shared configuration for Cilium network filter worker
 * Instances. Each new network connection (on each worker thread)
 * get's their own Instance, but they all share a common Config for
 * any given filter chain.
 */
class Config : Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::NetworkFilter& config, Server::Configuration::FactoryContext& context);
  Config(const Json::Object& config, Server::Configuration::FactoryContext& context);

  void log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

  Cilium::GoFilterSharedPtr proxylib_;
  TimeSource& time_source_;

private:
  Cilium::AccessLogSharedPtr access_log_;
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Implementation of a Cilium network filter.
 */
class Instance : public Network::Filter, Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config) : config_(config) {}

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance&, bool end_stream) override;

private:
  // helper to be used either directly from onNewConnection (no L7 LB),
  // or from upstream callback (l7 lb)
  bool enforceNetworkPolicy(const Cilium::CiliumPolicyFilterState* policy_fs,
                            Cilium::CiliumDestinationFilterState* dest_fs,
                            uint32_t destination_identity,
                            Network::Address::InstanceConstSharedPtr dst_address,
                            absl::string_view sni, StreamInfo::StreamInfo& stream_info);

  const ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  uint32_t remote_id_ = 0;
  uint16_t destination_port_ = 0;
  std::string l7proto_{};
  bool should_buffer_ = false;
  Buffer::OwnedImpl buffer_; // Buffer for initial connection data
  Cilium::GoFilter::InstancePtr go_parser_{};
  Cilium::AccessLog::Entry log_entry_{};
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
