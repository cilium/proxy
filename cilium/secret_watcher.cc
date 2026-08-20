#include "cilium/secret_watcher.h"

#include <fmt/format.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "envoy/api/api.h"
#include "envoy/common/callback.h"
#include "envoy/common/exception.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/tls.pb.h"
#include "envoy/secret/secret_provider.h"
#include "envoy/server/transport_socket_config.h"

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/config/datasource.h"
#include "source/common/protobuf/utility.h"
#include "source/common/tls/context_config_impl.h"
#include "source/common/tls/server_context_config_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "cilium/api/npds.pb.h"

namespace Envoy {
namespace Cilium {

namespace {

// SDS config used in production
envoy::config::core::v3::ConfigSource
getCiliumSDSConfig(const std::string&, const envoy::config::core::v3::ConfigSource& config_source) {
  // This is used in production, where the SDS config is always the same and does not need to
  // be overridden.
  return config_source;
}

GetSdsConfigFunc getSDSConfig = &getCiliumSDSConfig;

Secret::GenericSecretConfigProviderSharedPtr
secretProvider(Server::Configuration::TransportSocketFactoryContext& context,
               const envoy::config::core::v3::ConfigSource& config_source,
               const std::string& sds_name) {
  const envoy::config::core::v3::ConfigSource& sds_config_source =
      getSDSConfig(sds_name, config_source);
  return context.serverFactoryContext().secretManager().findOrCreateGenericSecretProvider(
      sds_config_source, sds_name, context.serverFactoryContext(), context.initManager());
}

} // namespace

void setSDSConfigFunc(GetSdsConfigFunc func) { getSDSConfig = func; }
void resetSDSConfigFunc() { getSDSConfig = &getCiliumSDSConfig; }

SecretWatcher::SecretWatcher(Server::Configuration::TransportSocketFactoryContext& context,
                             const envoy::config::core::v3::ConfigSource& config_source,
                             const std::string& sds_name)
    : context_(context), name_(sds_name),
      secret_provider_(secretProvider(context, config_source, sds_name)),
      update_secret_(readAndWatchSecret()) {}

SecretWatcher::~SecretWatcher() {
  if (!Thread::MainThread::isMainOrTestThread()) {
    ENVOY_LOG(error, "SecretWatcher: Destructor executing in a worker thread, while "
                     "only main thread should destruct xDS resources");
  }
  delete load();
}

Envoy::Common::CallbackHandlePtr SecretWatcher::readAndWatchSecret() {
  THROW_IF_NOT_OK(store());
  return secret_provider_->addUpdateCallback([this]() { return store(); });
}

absl::Status SecretWatcher::store() {
  const auto* secret = secret_provider_->secret();
  if (secret != nullptr) {
    Api::Api& api = context_.serverFactoryContext().api();
    auto string_or_error = Config::DataSource::read(secret->secret(), true, api);
    if (!string_or_error.ok()) {
      return string_or_error.status();
    }
    std::string* p = new std::string(string_or_error.value());
    std::string* old = ptr_.exchange(p, std::memory_order_release);
    if (old != nullptr) {
      // Delete old value after all worker threads have scheduled
      context_.serverFactoryContext().threadLocal().runOnAllWorkerThreads([]() {},
                                                                          [old]() { delete old; });
    }
  }
  return absl::OkStatus();
}

const std::string* SecretWatcher::load() const { return ptr_.load(std::memory_order_acquire); }

TLSContext::TLSContext(Server::Configuration::TransportSocketFactoryContext& context,
                       const std::string& name)
    : manager_(context.serverFactoryContext().sslContextManager()),
      scope_(context.serverFactoryContext().serverScope()),
      init_target_(fmt::format("TLS Context {} secret", name), []() {}) {}

namespace {

void setCommonConfig(const cilium::TLSContext& config,
                     const envoy::config::core::v3::ConfigSource& config_source,
                     envoy::extensions::transport_sockets::tls::v3::CommonTlsContext* tls_context) {
  if (!config.validation_context_sds_secret().empty()) {
    auto sds_secret = tls_context->mutable_validation_context_sds_secret_config();
    sds_secret->set_name(config.validation_context_sds_secret());
    auto* mutable_config_source = sds_secret->mutable_sds_config();
    *mutable_config_source = getSDSConfig(sds_secret->name(), config_source);
  } else if (!config.trusted_ca().empty()) {
    auto validation_context = tls_context->mutable_validation_context();
    auto trusted_ca = validation_context->mutable_trusted_ca();
    trusted_ca->set_inline_string(config.trusted_ca());
  }
  if (!config.tls_sds_secret().empty()) {
    auto sds_secret = tls_context->add_tls_certificate_sds_secret_configs();
    sds_secret->set_name(config.tls_sds_secret());
    auto* mutable_config_source = sds_secret->mutable_sds_config();
    *mutable_config_source = getSDSConfig(sds_secret->name(), config_source);
  } else if (!config.certificate_chain().empty()) {
    auto tls_certificate = tls_context->add_tls_certificates();
    auto certificate_chain = tls_certificate->mutable_certificate_chain();
    certificate_chain->set_inline_string(config.certificate_chain());
    if (!config.private_key().empty()) {
      auto private_key = tls_certificate->mutable_private_key();
      private_key->set_inline_string(config.private_key());
    } else {
      throw EnvoyException("TLS Context: missing private key");
    }
  }
  if (!config.alpn_protocols().empty()) {
    for (const std::string& protocol : config.alpn_protocols()) {
      ENVOY_LOG_MISC(trace, "setCommonConfig adding ALPN {}", protocol);
      tls_context->add_alpn_protocols(protocol);
    }
  }
}

} // namespace

DownstreamTLSContext::DownstreamTLSContext(
    Server::Configuration::TransportSocketFactoryContext& context,
    const envoy::config::core::v3::ConfigSource& config_source, const cilium::TLSContext& config)
    : TLSContext(context, "server") {
  // Server config always needs the TLS certificate to present to the client
  if (config.tls_sds_secret().empty() && config.certificate_chain().empty()) {
    throw EnvoyException("Downstream TLS Context: missing certificate chain");
  }

  envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext context_config;
  auto tls_context = context_config.mutable_common_tls_context();

  // Check if client certificate is required
  if (!config.validation_context_sds_secret().empty() || !config.trusted_ca().empty()) {
    auto require_tls_certificate = context_config.mutable_require_client_certificate();
    require_tls_certificate->set_value(true);
  }
  setCommonConfig(config, config_source, tls_context);

  for (int i = 0; i < config.server_names_size(); i++) {
    server_names_.emplace_back(config.server_names(i));
  }
  auto server_config_or_error = Extensions::TransportSockets::Tls::ServerContextConfigImpl::create(
      context_config, context, server_names_, false);
  // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
  THROW_IF_NOT_OK(server_config_or_error.status());
  server_config_ = std::move(server_config_or_error.value());

  auto create_server_context = [this]() {
    ENVOY_LOG(debug, "Server secret is updated.");
    auto ctx_or_error = manager_.createSslServerContext(scope_, *server_config_, nullptr);
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    THROW_IF_NOT_OK(ctx_or_error.status());
    auto ctx = std::move(ctx_or_error.value());
    {
      absl::WriterMutexLock l(&ssl_context_mutex_);
      std::swap(ctx, server_context_);
    }
    manager_.removeContext(ctx);
    init_target_.ready();
    return absl::OkStatus();
  };
  server_config_->setSecretUpdateCallback(create_server_context);
  if (server_config_->isReady()) {
    static_cast<void>(create_server_context());
  } else {
    context.initManager().add(init_target_);
  }
}

UpstreamTLSContext::UpstreamTLSContext(
    Server::Configuration::TransportSocketFactoryContext& context,
    const envoy::config::core::v3::ConfigSource& config_source, const cilium::TLSContext& config)
    : TLSContext(context, "client") {
  // Client context always needs the trusted CA for server certificate validation
  // TODO: Default to system default trusted CAs?
  if (config.validation_context_sds_secret().empty() && config.trusted_ca().empty()) {
    throw EnvoyException("Upstream TLS Context: missing trusted CA");
  }

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext context_config;
  auto tls_context = context_config.mutable_common_tls_context();
  setCommonConfig(config, config_source, tls_context);

  if (config.server_names_size() > 0) {
    if (config.server_names_size() > 1) {
      throw EnvoyException("Upstream TLS Context: more than one server name");
    }
    context_config.set_sni(config.server_names(0));
  }
  auto client_config_or_error =
      Extensions::TransportSockets::Tls::ClientContextConfigImpl::create(context_config, context);
  // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
  THROW_IF_NOT_OK(client_config_or_error.status());

  client_config_ = std::move(client_config_or_error.value());
  auto create_client_context = [this]() {
    ENVOY_LOG(debug, "Client secret is updated.");
    auto ctx_or_error = manager_.createSslClientContext(scope_, *client_config_);
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization)
    THROW_IF_NOT_OK(ctx_or_error.status());
    auto ctx = std::move(ctx_or_error.value());
    {
      absl::WriterMutexLock l(&ssl_context_mutex_);
      std::swap(ctx, client_context_);
    }
    manager_.removeContext(ctx);
    init_target_.ready();
    return absl::OkStatus();
  };
  client_config_->setSecretUpdateCallback(create_client_context);
  if (client_config_->isReady()) {
    static_cast<void>(create_client_context());
  } else {
    context.initManager().add(init_target_);
  }
}

namespace {

constexpr std::chrono::seconds PolicySecretCachePruneInterval{1};

template <typename Cache> void pruneExpired(Cache& cache) {
  for (auto it = cache.begin(); it != cache.end();) {
    if (it->second.expired()) {
      auto expired = it++;
      cache.erase(expired);
    } else {
      ++it;
    }
  }
}

template <typename Cache, typename Key, typename Factory>
auto getOrCreate(bool caching_enabled, Cache& cache, const Key& key, Factory&& factory) {
  if (!caching_enabled) {
    return factory();
  }

  auto it = cache.find(key);
  if (it != cache.end()) {
    if (auto cached = it->second.lock()) {
      return cached;
    }
    cache.erase(it);
  }

  auto value = factory();
  cache.emplace(key, value);
  return value;
}

} // namespace

class PolicySecretCache::Impl {
public:
  template <typename Context>
  using TLSContextMap =
      absl::flat_hash_map<cilium::TLSContext, std::weak_ptr<Context>, MessageUtil, MessageUtil>;
  using SecretWatcherMap = absl::flat_hash_map<std::string, std::weak_ptr<SecretWatcher>>;

  Impl(std::shared_ptr<Server::Configuration::TransportSocketFactoryContext> context,
       std::reference_wrapper<const envoy::config::core::v3::ConfigSource> config_source,
       bool caching_enabled)
      : context_(std::move(context)), config_source_(config_source),
        caching_enabled_(caching_enabled),
        next_prune_time_(context_->serverFactoryContext().timeSource().monotonicTime() +
                         PolicySecretCachePruneInterval) {}

  void reset() {
    ASSERT_IS_MAIN_OR_TEST_THREAD();
    downstream_cache_.clear();
    upstream_cache_.clear();
    secret_watcher_cache_.clear();
    next_prune_time_ = context_->serverFactoryContext().timeSource().monotonicTime() +
                       PolicySecretCachePruneInterval;
  }

  void prune() {
    ASSERT_IS_MAIN_OR_TEST_THREAD();
    if (!caching_enabled_) {
      return;
    }
    const MonotonicTime now = context_->serverFactoryContext().timeSource().monotonicTime();
    if (now < next_prune_time_) {
      return;
    }

    // Advance the deadline before scanning so that frequent policy updates cannot trigger more
    // than one complete cache scan per interval.
    next_prune_time_ = now + PolicySecretCachePruneInterval;
    pruneExpired(downstream_cache_);
    pruneExpired(upstream_cache_);
    pruneExpired(secret_watcher_cache_);
  }

  std::shared_ptr<Server::Configuration::TransportSocketFactoryContext> context_;
  std::reference_wrapper<const envoy::config::core::v3::ConfigSource> config_source_;
  const bool caching_enabled_;
  TLSContextMap<DownstreamTLSContext> downstream_cache_;
  TLSContextMap<UpstreamTLSContext> upstream_cache_;
  SecretWatcherMap secret_watcher_cache_;
  MonotonicTime next_prune_time_;
};

PolicySecretCache::PolicySecretCache(
    std::shared_ptr<Server::Configuration::TransportSocketFactoryContext> context,
    std::reference_wrapper<const envoy::config::core::v3::ConfigSource> config_source,
    bool caching_enabled)
    : impl_(std::make_unique<Impl>(std::move(context), config_source, caching_enabled)) {}

PolicySecretCache::~PolicySecretCache() = default;

void PolicySecretCache::reset() { impl_->reset(); }

void PolicySecretCache::prune() { impl_->prune(); }

DownstreamTLSContextSharedPtr
PolicySecretCache::getOrCreateDownstream(const cilium::TLSContext& config) const {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return getOrCreate(impl_->caching_enabled_, impl_->downstream_cache_, config, [this, &config]() {
    return DownstreamTLSContextSharedPtr(
        new DownstreamTLSContext(*impl_->context_, impl_->config_source_.get(), config));
  });
}

UpstreamTLSContextSharedPtr
PolicySecretCache::getOrCreateUpstream(const cilium::TLSContext& config) const {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return getOrCreate(impl_->caching_enabled_, impl_->upstream_cache_, config, [this, &config]() {
    return UpstreamTLSContextSharedPtr(
        new UpstreamTLSContext(*impl_->context_, impl_->config_source_.get(), config));
  });
}

SecretWatcherSharedPtr
PolicySecretCache::getOrCreateSecretWatcher(const std::string& sds_name) const {
  ASSERT_IS_MAIN_OR_TEST_THREAD();
  return getOrCreate(impl_->caching_enabled_, impl_->secret_watcher_cache_, sds_name,
                     [this, &sds_name]() {
                       return std::make_shared<SecretWatcher>(
                           *impl_->context_, impl_->config_source_.get(), sds_name);
                     });
}

} // namespace Cilium
} // namespace Envoy
