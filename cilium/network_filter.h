#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/server/filter_config.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/logger.h"

#include "cilium/accesslog.h"
#include "cilium/api/network_filter.pb.h"
#include "cilium/conntrack.h"
#include "cilium/network_policy.h"
#include "cilium/proxylib.h"
#include "cilium/proxymap.h"

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
  virtual ~Config();

  void Log(Cilium::AccessLog::Entry&, ::cilium::EntryType);

  Cilium::GoFilterSharedPtr proxylib_;
  TimeSource& time_source_;
private:
  Cilium::AccessLog *access_log_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a Cilium network filter.
 */
class Instance : public Network::Filter, public Network::ConnectionCallbacks,
                 Logger::Loggable<Logger::Id::filter> {
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
  
  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  const ConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  Cilium::ProxyMapSharedPtr maps_{};
  std::string l7proto_{};
  uint16_t proxy_port_ = 0;
  Cilium::GoFilter::InstancePtr go_parser_{};
  Cilium::PortPolicyConstSharedPtr port_policy_{};
  Cilium::AccessLog::Entry log_entry_{};
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
