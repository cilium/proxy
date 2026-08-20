#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/callback.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/ssl/private_key/private_key.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"
#include "source/common/init/target_impl.h"

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "cilium/api/npds.pb.h"

namespace Envoy {
namespace Cilium {

class PolicySecretCache;

// Facility for SDS config override for testing
using GetSdsConfigFunc = std::function<const envoy::config::core::v3::ConfigSource(
    const std::string&, const envoy::config::core::v3::ConfigSource&)>;
void setSDSConfigFunc(GetSdsConfigFunc);
void resetSDSConfigFunc();

class SecretWatcher : public Logger::Loggable<Logger::Id::config> {
public:
  SecretWatcher(Server::Configuration::TransportSocketFactoryContext& context,
                const envoy::config::core::v3::ConfigSource& config_source,
                const std::string& sds_name);
  ~SecretWatcher();

  const std::string& name() const { return name_; }
  const std::string* value() const { return load(); }

private:
  Envoy::Common::CallbackHandlePtr readAndWatchSecret();
  absl::Status store();
  const std::string* load() const;

  Server::Configuration::TransportSocketFactoryContext& context_;
  const std::string name_;
  std::atomic<std::string*> ptr_{nullptr};
  Secret::GenericSecretConfigProviderSharedPtr secret_provider_;
  Envoy::Common::CallbackHandlePtr update_secret_;
};
using SecretWatcherSharedPtr = std::shared_ptr<SecretWatcher>;

// private base class for the common bits
class TLSContext : public Logger::Loggable<Logger::Id::config> {
public:
  TLSContext() = delete;

protected:
  TLSContext(Server::Configuration::TransportSocketFactoryContext& context,
             const std::string& name);

  Envoy::Ssl::ContextManager& manager_;
  Stats::Scope& scope_;
  Init::TargetImpl init_target_;
  absl::Mutex ssl_context_mutex_;
};

class DownstreamTLSContext : protected TLSContext {
public:
  ~DownstreamTLSContext() { manager_.removeContext(server_context_); }

  const Ssl::ContextConfig& getTlsContextConfig() const { return *server_config_; }

  Ssl::ContextSharedPtr getTlsContext() const {
    absl::ReaderMutexLock l(&const_cast<DownstreamTLSContext*>(this)->ssl_context_mutex_);
    return server_context_;
  }

private:
  friend class PolicySecretCache;

  DownstreamTLSContext(Server::Configuration::TransportSocketFactoryContext& context,
                       const envoy::config::core::v3::ConfigSource& config_source,
                       const cilium::TLSContext& config);

  Ssl::ServerContextConfigPtr server_config_;
  std::vector<std::string> server_names_;
  Ssl::ServerContextSharedPtr server_context_ ABSL_GUARDED_BY(ssl_context_mutex_);
};
using DownstreamTLSContextSharedPtr = std::shared_ptr<DownstreamTLSContext>;

class UpstreamTLSContext : protected TLSContext {
public:
  ~UpstreamTLSContext() { manager_.removeContext(client_context_); }

  const Ssl::ContextConfig& getTlsContextConfig() const { return *client_config_; }
  Ssl::ContextSharedPtr getTlsContext() const {
    absl::ReaderMutexLock l(&const_cast<UpstreamTLSContext*>(this)->ssl_context_mutex_);
    return client_context_;
  }

private:
  friend class PolicySecretCache;

  UpstreamTLSContext(Server::Configuration::TransportSocketFactoryContext& context,
                     const envoy::config::core::v3::ConfigSource& config_source,
                     const cilium::TLSContext& config);

  Ssl::ClientContextConfigPtr client_config_;
  Ssl::ClientContextSharedPtr client_context_ ABSL_GUARDED_BY(ssl_context_mutex_);
};
using UpstreamTLSContextSharedPtr = std::shared_ptr<UpstreamTLSContext>;

// Main-thread-only cache of secret-derived resources constructed for NetworkPolicy rules. The
// cache owns the factory context and observes the active NPDS config source for the lifetime of its
// owning NetworkPolicyMapImpl.
class PolicySecretCache {
public:
  PolicySecretCache(
      std::shared_ptr<Server::Configuration::TransportSocketFactoryContext> context,
      std::reference_wrapper<const envoy::config::core::v3::ConfigSource> config_source,
      bool caching_enabled);
  ~PolicySecretCache();

  PolicySecretCache(const PolicySecretCache&) = delete;
  PolicySecretCache& operator=(const PolicySecretCache&) = delete;

  // Must only be called from Envoy's main thread (or the designated test thread).
  // Clears all resources cached for the previous NPDS stream generation.
  void reset();

  // Must only be called from Envoy's main thread (or the designated test thread), after a policy
  // update. Pruning is internally rate-limited.
  void prune();

  // Must only be called from Envoy's main thread (or the designated test thread).
  DownstreamTLSContextSharedPtr getOrCreateDownstream(const cilium::TLSContext& config) const;

  // Must only be called from Envoy's main thread (or the designated test thread).
  UpstreamTLSContextSharedPtr getOrCreateUpstream(const cilium::TLSContext& config) const;

  // Must only be called from Envoy's main thread (or the designated test thread).
  // Within one NPDS stream, the SDS resource name uniquely identifies the effective config source
  // and generic secret value observed by all HeaderMatches using that name.
  SecretWatcherSharedPtr getOrCreateSecretWatcher(const std::string& sds_name) const;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace Cilium
} // namespace Envoy
