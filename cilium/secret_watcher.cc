#include "cilium/secret_watcher.h"

#include "source/common/config/datasource.h"

#include "cilium/grpc_subscription.h"

namespace Envoy {
namespace Cilium {

namespace {

// SDS config used in production
envoy::config::core::v3::ConfigSource getCiliumSDSConfig(const std::string&) {
  /* returned config_source has initial_fetch_timeout left at default 15 seconds. */
  return Cilium::cilium_xds_api_config;
}

Secret::GenericSecretConfigProviderSharedPtr
secretProvider(Server::Configuration::TransportSocketFactoryContext& context,
               const std::string& sds_name) {
  envoy::config::core::v3::ConfigSource config_source = getSDSConfig(sds_name);
  return context.secretManager().findOrCreateGenericSecretProvider(config_source, sds_name, context,
                                                                   context.initManager());
}

} // namespace

getSDSConfigFunc getSDSConfig = &getCiliumSDSConfig;
void setSDSConfigFunc(getSDSConfigFunc func) { getSDSConfig = func; }
void resetSDSConfigFunc() { getSDSConfig = &getCiliumSDSConfig; }

SecretWatcher::SecretWatcher(const NetworkPolicyMap& parent, const std::string& sds_name)
    : parent_(parent), name_(sds_name),
      secret_provider_(secretProvider(parent.transportFactoryContext(), sds_name)),
      update_secret_(readAndWatchSecret()) {}

SecretWatcher::~SecretWatcher() { delete load(); }

Envoy::Common::CallbackHandlePtr SecretWatcher::readAndWatchSecret() {
  store();
  return secret_provider_->addUpdateCallback([this]() { store(); });
}

void SecretWatcher::store() {
  const auto* secret = secret_provider_->secret();
  if (secret != nullptr) {
    Api::Api& api = parent_.transportFactoryContext().serverFactoryContext().api();
    std::string* p = new std::string(Config::DataSource::read(secret->secret(), true, api));
    std::string* old = ptr_.exchange(p, std::memory_order_release);
    if (old != nullptr) {
      // Delete old value after all threads have scheduled
      parent_.runAfterAllThreads([old]() { delete old; });
    }
  }
}

const std::string* SecretWatcher::load() const { return ptr_.load(std::memory_order_acquire); }

TLSContext::TLSContext(const NetworkPolicyMap& parent, const std::string& name)
    : manager_(parent.transportFactoryContext().sslContextManager()),
      scope_(parent.transportFactoryContext().serverFactoryContext().serverScope()),
      init_target_(fmt::format("TLS Context {} secret", name), []() {}) {}

namespace {

void setCommonConfig(const cilium::TLSContext config,
                     envoy::extensions::transport_sockets::tls::v3::CommonTlsContext* tls_context) {
  if (config.validation_context_sds_secret() != "") {
    auto sds_secret = tls_context->mutable_validation_context_sds_secret_config();
    sds_secret->set_name(config.validation_context_sds_secret());
    auto* config_source = sds_secret->mutable_sds_config();
    *config_source = getSDSConfig(config.validation_context_sds_secret());
  } else if (config.trusted_ca() != "") {
    auto validation_context = tls_context->mutable_validation_context();
    auto trusted_ca = validation_context->mutable_trusted_ca();
    trusted_ca->set_inline_string(config.trusted_ca());
  }
  if (config.tls_sds_secret() != "") {
    auto sds_secret = tls_context->add_tls_certificate_sds_secret_configs();
    sds_secret->set_name(config.tls_sds_secret());
    auto* config_source = sds_secret->mutable_sds_config();
    *config_source = getSDSConfig(config.tls_sds_secret());
  } else if (config.certificate_chain() != "") {
    auto tls_certificate = tls_context->add_tls_certificates();
    auto certificate_chain = tls_certificate->mutable_certificate_chain();
    certificate_chain->set_inline_string(config.certificate_chain());
    if (config.private_key() != "") {
      auto private_key = tls_certificate->mutable_private_key();
      private_key->set_inline_string(config.private_key());
    } else {
      throw EnvoyException("TLS Context: missing private key");
    }
  }
}

} // namespace

DownstreamTLSContext::DownstreamTLSContext(const NetworkPolicyMap& parent,
                                           const cilium::TLSContext config)
    : TLSContext(parent, "server") {
  // Server config always needs the TLS certificate to present to the client
  if (config.tls_sds_secret() == "" && config.certificate_chain() == "")
    throw EnvoyException("Downstream TLS Context: missing certificate chain");

  envoy::extensions::transport_sockets::tls::v3::DownstreamTlsContext context_config;
  auto tls_context = context_config.mutable_common_tls_context();

  // Check if client certificate is required
  if (config.validation_context_sds_secret() != "" || config.trusted_ca() != "") {
    auto require_tls_certificate = context_config.mutable_require_client_certificate();
    require_tls_certificate->set_value(true);
  }
  setCommonConfig(config, tls_context);

  for (int i = 0; i < config.server_names_size(); i++) {
    server_names_.emplace_back(config.server_names(i));
  }
  server_config_ = std::make_unique<Extensions::TransportSockets::Tls::ServerContextConfigImpl>(
      context_config, parent.transportFactoryContext());
  auto create_server_context = [this]() {
    ENVOY_LOG(debug, "Server secret is updated.");
    auto ctx = manager_.createSslServerContext(scope_, *server_config_, server_names_);
    {
      absl::WriterMutexLock l(&ssl_context_mutex_);
      std::swap(ctx, server_context_);
    }
    manager_.removeContext(ctx);
    init_target_.ready();
  };
  server_config_->setSecretUpdateCallback(create_server_context);
  if (server_config_->isReady())
    create_server_context();
  else
    parent.transportFactoryContext().initManager().add(init_target_);
}

UpstreamTLSContext::UpstreamTLSContext(const NetworkPolicyMap& parent, cilium::TLSContext config)
    : TLSContext(parent, "client") {
  // Client context always needs the trusted CA for server certificate validation
  // TODO: Default to system default trusted CAs?
  if (config.validation_context_sds_secret() == "" && config.trusted_ca() == "")
    throw EnvoyException("Upstream TLS Context: missing trusted CA");

  envoy::extensions::transport_sockets::tls::v3::UpstreamTlsContext context_config;
  auto tls_context = context_config.mutable_common_tls_context();
  setCommonConfig(config, tls_context);

  if (config.server_names_size() > 0) {
    if (config.server_names_size() > 1) {
      throw EnvoyException("Upstream TLS Context: more than one server name");
    }
    context_config.set_sni(config.server_names(0));
  }
  client_config_ = std::make_unique<Extensions::TransportSockets::Tls::ClientContextConfigImpl>(
      context_config, parent.transportFactoryContext());
  auto create_client_context = [this]() {
    ENVOY_LOG(debug, "Client secret is updated.");
    auto ctx = manager_.createSslClientContext(scope_, *client_config_);
    {
      absl::WriterMutexLock l(&ssl_context_mutex_);
      std::swap(ctx, client_context_);
    }
    manager_.removeContext(ctx);
    init_target_.ready();
  };
  client_config_->setSecretUpdateCallback(create_client_context);
  if (client_config_->isReady())
    create_client_context();
  else
    parent.transportFactoryContext().initManager().add(init_target_);
}

} // namespace Cilium
} // namespace Envoy
