#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "envoy/common/callback.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/ssl/context.h"
#include "envoy/ssl/context_config.h"
#include "envoy/ssl/context_manager.h"
#include "envoy/stats/scope.h"

#include "source/common/common/logger.h"
#include "source/common/init/target_impl.h"

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "cilium/api/npds.pb.h"
#include "cilium/network_policy.h"

namespace Envoy {
namespace Cilium {

// Facility for SDS config override for testing
typedef envoy::config::core::v3::ConfigSource (*getSDSConfigFunc)(const std::string& name);
extern getSDSConfigFunc getSDSConfig;
void setSDSConfigFunc(getSDSConfigFunc);
void resetSDSConfigFunc();

class SecretWatcher : public Logger::Loggable<Logger::Id::config> {
public:
  SecretWatcher(const NetworkPolicyMapImpl& parent, const std::string& sds_name);
  ~SecretWatcher();

  const std::string& name() const { return name_; }
  const std::string* value() const { return load(); }

private:
  Envoy::Common::CallbackHandlePtr readAndWatchSecret();
  absl::Status store();
  const std::string* load() const;

  const NetworkPolicyMapImpl& parent_;
  const std::string name_;
  std::atomic<std::string*> ptr_{nullptr};
  Secret::GenericSecretConfigProviderSharedPtr secret_provider_;
  Envoy::Common::CallbackHandlePtr update_secret_;
};
using SecretWatcherPtr = std::unique_ptr<SecretWatcher>;

// private base class for the common bits
class TLSContext : public Logger::Loggable<Logger::Id::config> {
public:
  TLSContext() = delete;

protected:
  TLSContext(const NetworkPolicyMapImpl& parent, const std::string& name);

  Envoy::Ssl::ContextManager& manager_;
  Stats::Scope& scope_;
  Init::TargetImpl init_target_;
  absl::Mutex ssl_context_mutex_;
};

class DownstreamTLSContext : protected TLSContext {
public:
  DownstreamTLSContext(const NetworkPolicyMapImpl& parent, const cilium::TLSContext config);
  ~DownstreamTLSContext() { manager_.removeContext(server_context_); }

  const Ssl::ContextConfig& getTlsContextConfig() const { return *server_config_; }

  Ssl::ContextSharedPtr getTlsContext() const {
    absl::ReaderMutexLock l(&const_cast<DownstreamTLSContext*>(this)->ssl_context_mutex_);
    return server_context_;
  }

private:
  Ssl::ServerContextConfigPtr server_config_;
  std::vector<std::string> server_names_;
  Ssl::ServerContextSharedPtr server_context_ ABSL_GUARDED_BY(ssl_context_mutex_){};
};
using DownstreamTLSContextPtr = std::unique_ptr<DownstreamTLSContext>;

class UpstreamTLSContext : protected TLSContext {
public:
  UpstreamTLSContext(const NetworkPolicyMapImpl& parent, cilium::TLSContext config);
  ~UpstreamTLSContext() { manager_.removeContext(client_context_); }

  const Ssl::ContextConfig& getTlsContextConfig() const { return *client_config_; }
  Ssl::ContextSharedPtr getTlsContext() const {
    absl::ReaderMutexLock l(&const_cast<UpstreamTLSContext*>(this)->ssl_context_mutex_);
    return client_context_;
  }

private:
  Ssl::ClientContextConfigPtr client_config_;
  Ssl::ClientContextSharedPtr client_context_ ABSL_GUARDED_BY(ssl_context_mutex_){};
};
using UpstreamTLSContextPtr = std::unique_ptr<UpstreamTLSContext>;

} // namespace Cilium
} // namespace Envoy
