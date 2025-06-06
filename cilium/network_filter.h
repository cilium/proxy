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
  Config(const ::cilium::NetworkFilter& config, Server::Configuration::FactoryContext& context);
  Config(const Json::Object& config, Server::Configuration::FactoryContext& context);

  void log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

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
  const ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  uint32_t remote_id_ = 0;
  uint16_t destination_port_ = 0;
  Cilium::AccessLog::Entry log_entry_{};
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
