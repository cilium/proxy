#pragma once

#include <cstdint>
#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/time.h"
#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/server/factory_context.h"

#include "source/common/common/logger.h"

#include "cilium/accesslog.h"
#include "cilium/api/accesslog.pb.h"
#include "cilium/api/network_filter.pb.h"

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
  Config(const ::cilium::NetworkFilter& config, bool is_upstream,
         Server::Configuration::ServerFactoryContext& context);

  void log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

  bool is_upstream_;
  TimeSource& time_source_;

private:
  Cilium::AccessLogSharedPtr access_log_{};
};

using ConfigSharedPtr = std::shared_ptr<Config>;

/**
 * Implementation of a Cilium network filter.
 */
class Instance : public Network::ReadFilter, Logger::Loggable<Logger::Id::filter> {
public:
  Instance(const ConfigSharedPtr& config) : config_(config) {}

  // Network::ReadFilter
  bool allowConnect(Network::Connection& conn,
                    const Network::Address::InstanceConstSharedPtr& destination_address,
                    StreamInfo::StreamInfo& stream_info) override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  Network::FilterStatus onNewConnection() override;
  Network::FilterStatus onData(Buffer::Instance&, bool end_stream) override;

private:
  const ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  Cilium::AccessLog::Entry log_entry_{};
  absl::flat_hash_map<std::pair<uint32_t, uint16_t>, bool> policy_cache_;
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
