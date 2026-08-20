#include <gmock/gmock.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "envoy/common/optref.h"
#include "envoy/config/core/v3/config_source.pb.h"
#include "envoy/extensions/transport_sockets/tls/v3/secret.pb.h"
#include "envoy/init/manager.h"
#include "envoy/server/factory_context.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/config/decoded_resource_impl.h"
#include "source/common/memory/stats.h"
#include "source/common/secret/sds_api.h" // NOLINT

#include "test/mocks/secret/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/environment.h"

#include "absl/strings/str_cat.h"
#include "benchmark/benchmark.h"
#include "cilium/api/npds.pb.h"
#include "cilium/network_policy.h"
#include "tests/cilium_test_peer.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace Envoy {
namespace Cilium {

// Cilium XDS API config source. Used for all Cilium XDS.
extern const envoy::config::core::v3::ConfigSource CILIUM_XDS_API_CONFIG;

namespace {
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::ReturnRef;

constexpr uint64_t kPolicyCount = 1000;
constexpr char kSharedValidationContextSdsSecret[] = "benchmark-shared-ca";
constexpr char kSharedHeaderSdsSecret[] = "benchmark-shared-header";
constexpr char kSdsVersion[] = "benchmark-secret-version";
constexpr size_t kHeaderSecretValueSize = 256;

envoy::service::discovery::v3::DiscoveryResponse makeNpdsResponse(bool use_header_secret) {
  envoy::service::discovery::v3::DiscoveryResponse response;
  response.set_version_info("benchmark-version");

  for (uint64_t index = 0; index < kPolicyCount; ++index) {
    cilium::NetworkPolicy policy;
    policy.set_endpoint_id(index + 1);
    policy.add_endpoint_ips(absl::StrCat("10.0.", index / 250, ".", index % 250 + 1));

    auto* port_policy = use_header_secret ? policy.add_ingress_per_port_policies()
                                          : policy.add_egress_per_port_policies();
    port_policy->set_port(use_header_secret ? 80 : 443);
    auto* rule = port_policy->add_rules();
    rule->add_remote_policies(42);
    if (use_header_secret) {
      auto* header_match = rule->mutable_http_rules()->add_http_rules()->add_header_matches();
      header_match->set_name("x-benchmark-secret");
      header_match->set_value_sds_secret(kSharedHeaderSdsSecret);
    } else {
      rule->mutable_upstream_tls_context()->set_validation_context_sds_secret(
          kSharedValidationContextSdsSecret);
    }

    response.add_resources()->PackFrom(policy);
  }
  return response;
}

void processNpdsUpdateWith1000Policies(benchmark::State& state, bool policy_secret_cache_enabled,
                                       bool use_header_secret) {
  NiceMock<Server::Configuration::MockFactoryContext> factory_context;
  NiceMock<Secret::MockSecretManager> secret_manager;
  ON_CALL(factory_context.server_factory_context_, secretManager())
      .WillByDefault(ReturnRef(secret_manager));

  std::string runfiles_error;
  std::error_code executable_path_error;
  const std::filesystem::path executable_path =
      std::filesystem::read_symlink("/proc/self/exe", executable_path_error);
  if (executable_path_error) {
    state.SkipWithError(executable_path_error.message());
    return;
  }
  std::unique_ptr<bazel::tools::cpp::runfiles::Runfiles> runfiles(
      bazel::tools::cpp::runfiles::Runfiles::Create(executable_path.string(), &runfiles_error));
  if (runfiles == nullptr) {
    state.SkipWithError(runfiles_error);
    return;
  }
  TestEnvironment::setRunfiles(runfiles.get());
  const std::string trusted_ca = TestEnvironment::readFileToStringForTest(
      TestEnvironment::runfilesPath("test/config/integration/certs/upstreamcacert.pem"));

  // Model an SDS resource that has already delivered the shared CA. The test policy contains only
  // the SDS resource name; the CA payload is owned once by this shared dynamic provider.
  auto validation_context_provider = Secret::CertificateValidationContextSdsApi::create(
      factory_context.server_factory_context_, CILIUM_XDS_API_CONFIG,
      kSharedValidationContextSdsSecret, []() {}, false);
  auto validation_context_secret =
      std::make_unique<envoy::extensions::transport_sockets::tls::v3::Secret>();
  validation_context_secret->set_name(kSharedValidationContextSdsSecret);
  validation_context_secret->mutable_validation_context()->mutable_trusted_ca()->set_inline_string(
      trusted_ca);
  Config::DecodedResourcesWrapper decoded_sds_resources;
  decoded_sds_resources.pushBack(std::make_unique<Config::DecodedResourceImpl>(
      std::move(validation_context_secret), kSharedValidationContextSdsSecret,
      std::vector<std::string>{}, kSdsVersion));
  const auto sds_status = static_cast<Config::SubscriptionCallbacks&>(*validation_context_provider)
                              .onConfigUpdate(decoded_sds_resources.refvec_, kSdsVersion);
  if (!sds_status.ok()) {
    state.SkipWithError(sds_status.ToString());
    return;
  }

  ON_CALL(secret_manager, findOrCreateCertificateValidationContextProvider(_, _, _, _))
      .WillByDefault(
          Invoke([validation_context_provider](
                     const envoy::config::core::v3::ConfigSource&, const std::string&,
                     Server::Configuration::ServerFactoryContext&, Init::Manager& init_manager) {
            // SecretManagerImpl adds the shared provider target to each caller's init manager even
            // when the provider already exists.
            init_manager.add(*validation_context_provider->initTarget());
            return validation_context_provider;
          }));

  // Use a synthetic, non-credential value representative of an authorization-style HTTP header.
  // This is intentionally much smaller than the CA payload used by the TLS context scenario.
  const std::string header_secret_value(kHeaderSecretValueSize, 'x');
  auto generic_secret_provider = Secret::GenericSecretSdsApi::create(
      factory_context.server_factory_context_, CILIUM_XDS_API_CONFIG, kSharedHeaderSdsSecret,
      []() {}, false);
  auto generic_secret = std::make_unique<envoy::extensions::transport_sockets::tls::v3::Secret>();
  generic_secret->set_name(kSharedHeaderSdsSecret);
  generic_secret->mutable_generic_secret()->mutable_secret()->set_inline_string(
      header_secret_value);
  Config::DecodedResourcesWrapper decoded_generic_secret_resources;
  decoded_generic_secret_resources.pushBack(std::make_unique<Config::DecodedResourceImpl>(
      std::move(generic_secret), kSharedHeaderSdsSecret, std::vector<std::string>{}, kSdsVersion));
  const auto generic_secret_status =
      static_cast<Config::SubscriptionCallbacks&>(*generic_secret_provider)
          .onConfigUpdate(decoded_generic_secret_resources.refvec_, kSdsVersion);
  if (!generic_secret_status.ok()) {
    state.SkipWithError(generic_secret_status.ToString());
    return;
  }

  ON_CALL(secret_manager, findOrCreateGenericSecretProvider(_, _, _, _))
      .WillByDefault(Invoke([generic_secret_provider](const envoy::config::core::v3::ConfigSource&,
                                                      const std::string&,
                                                      Server::Configuration::ServerFactoryContext&,
                                                      OptRef<Init::Manager> init_manager) {
        if (init_manager.has_value()) {
          init_manager->add(*generic_secret_provider->initTarget());
        } else {
          generic_secret_provider->start();
        }
        return generic_secret_provider;
      }));

  const auto response = makeNpdsResponse(use_header_secret);
  NetworkPolicyDecoder decoder;
  auto decoded_resources_or_error = Config::DecodedResourcesWrapper::create(
      decoder, response.resources(), response.version_info());
  if (!decoded_resources_or_error.ok()) {
    state.SkipWithError(decoded_resources_or_error.status().ToString());
    return;
  }
  auto decoded_resources = std::move(decoded_resources_or_error.value());
  uint64_t total_retained_memory = 0;
  auto& config_tracker_callbacks =
      factory_context.server_factory_context_.admin_.config_tracker_.config_tracker_callbacks_;

  // Exclude one-time TLS/library initialization from the retained-memory comparison and warm the
  // same code path before Google Benchmark calibrates the measured iterations.
  {
    config_tracker_callbacks.clear();
    auto policy_map = std::make_shared<NetworkPolicyMap>(factory_context, CILIUM_XDS_API_CONFIG,
                                                         false, policy_secret_cache_enabled);
    CiliumTestPeer::resetStream(*policy_map);
    const auto warmup_status =
        CiliumTestPeer::subscriptionCallbacks(*policy_map)
            .onConfigUpdate(decoded_resources->refvec_, response.version_info());
    if (!warmup_status.ok()) {
      state.SkipWithError(warmup_status.ToString());
      return;
    }
  }

  for (auto _ : state) { // NOLINT: Silences warning about dead store.
    // Recreate the policy map outside the measured interval so that every iteration measures a
    // first update, without whole-policy reuse from a previous iteration. The memory counter is
    // retained live heap allocated by the update; response construction and decoding are excluded.
    state.PauseTiming();
    // MockConfigTracker does not remove callback keys when its EntryOwner is destroyed.
    config_tracker_callbacks.clear();
    auto policy_map = std::make_shared<NetworkPolicyMap>(factory_context, CILIUM_XDS_API_CONFIG,
                                                         false, policy_secret_cache_enabled);
    CiliumTestPeer::resetStream(*policy_map);
    auto& callbacks = CiliumTestPeer::subscriptionCallbacks(*policy_map);
    const uint64_t memory_before = Memory::Stats::totalCurrentlyAllocated();
    state.ResumeTiming();

    const auto status =
        callbacks.onConfigUpdate(decoded_resources->refvec_, response.version_info());
    benchmark::DoNotOptimize(status);

    state.PauseTiming();
    const uint64_t memory_after = Memory::Stats::totalCurrentlyAllocated();
    policy_map.reset();
    if (!status.ok()) {
      state.ResumeTiming();
      state.SkipWithError(status.ToString());
      return;
    }
    if (memory_after < memory_before) {
      state.ResumeTiming();
      state.SkipWithError("allocator reported less live memory after the NPDS update");
      return;
    }
    total_retained_memory += memory_after - memory_before;
    state.ResumeTiming();
  }

  const double average_retained_memory =
      static_cast<double>(total_retained_memory) / state.iterations();
  state.counters["retained_memory_bytes"] = benchmark::Counter(
      average_retained_memory, benchmark::Counter::kDefaults, benchmark::Counter::kIs1024);
  state.counters["retained_memory_per_policy_bytes"] =
      benchmark::Counter(average_retained_memory / kPolicyCount, benchmark::Counter::kDefaults,
                         benchmark::Counter::kIs1024);
  state.SetItemsProcessed(static_cast<int64_t>(state.iterations()) * kPolicyCount);
}

BENCHMARK_CAPTURE(processNpdsUpdateWith1000Policies, TlsContextCacheEnabled, true, false)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(processNpdsUpdateWith1000Policies, TlsContextCacheDisabled, false, false)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(processNpdsUpdateWith1000Policies, HeaderSecretCacheEnabled, true, true)
    ->Unit(benchmark::kMillisecond);
BENCHMARK_CAPTURE(processNpdsUpdateWith1000Policies, HeaderSecretCacheDisabled, false, true)
    ->Unit(benchmark::kMillisecond);

} // namespace
} // namespace Cilium
} // namespace Envoy
