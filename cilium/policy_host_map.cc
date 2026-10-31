#include "cilium/policy_host_map.h"

#include <charconv>
#include <fmt/format.h>

#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

#include "envoy/common/exception.h"
#include "envoy/event/dispatcher.h"

#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace Envoy {
namespace Cilium {
namespace {

static constexpr absl::string_view NetworkPolicyHostsTypeUrl =
    "type.googleapis.com/cilium.NetworkPolicyHosts";

void insertHosts(HostMapBuilder& map, const cilium::NetworkPolicyHosts& proto) {
  try {
    map.insert(proto.policy(), proto.host_addresses());
  } catch (const EnvoyException& e) {
    throw EnvoyException(fmt::format("NetworkPolicyHosts: {}", e.what()));
  }
}

} // namespace

uint64_t PolicyHostMap::instance_id_ = 0;

PolicyHostMap::PolicyHostMap(Server::Configuration::CommonFactoryContext& context,
                             const envoy::config::core::v3::ConfigSource& config_source,
                             bool subscribe)
    : ManagedGrpcSubscription(
          NetworkPolicyHostsTypeUrl, config_source,
          [](absl::string_view) { return std::make_shared<Cilium::PolicyHostDecoder>(); }, context,
          context.serverScope().createScope("cilium.nphds."), subscribe),
      tls_(context.threadLocal().allocateSlot()),
      name_(absl::StrCat("cilium.hostmap.", fmt::format("{}", instance_id_ + 1), ".")),
      host_stats_scope_(context.serverScope().createScope("cilium.hostmap.")),
      stats_({CILIUM_POLICY_HOSTS_STATS(POOL_COUNTER(*host_stats_scope_))}) {
  instance_id_++;
  ENVOY_LOG(debug, "PolicyHostMap({}) created.", name_);

  auto empty_map = std::make_shared<ThreadLocalHostMap>(HostMap{});
  tls_->set([empty_map](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return empty_map;
  });
  if (subscribe) {
    start();
  }
}

absl::Status
PolicyHostMap::onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& added_resources,
                              const Protobuf::RepeatedPtrField<std::string>& removed_resources,
                              const std::string& system_version_info) {
  const auto stream_generation = streamGeneration();
  const bool is_new_stream = stream_generation != accepted_stream_generation_;
  ENVOY_LOG(
      debug,
      "PolicyHostMap::onConfigUpdate({}), {} added_resources, {} removed_resources, version: {}, "
      "stream: {}, accepted_stream: {}, is_new_stream: {}",
      name_, added_resources.size(), removed_resources.size(), system_version_info,
      stream_generation, accepted_stream_generation_, is_new_stream);

  HostMapBuilder newmap(is_new_stream ? nullptr : getHostMap());

  absl::flat_hash_set<uint64_t> to_remove;
  to_remove.reserve(added_resources.size() + removed_resources.size());

  for (const auto& name : removed_resources) {
    uint64_t nid = 0;
    auto [ptr, ec] = std::from_chars(name.data(), name.data() + name.size(), nid);
    if (ec != std::errc{} || ptr != name.data() + name.size()) {
      throw EnvoyException(fmt::format("Invalid removed resource name '{}'", name));
    }
    ENVOY_LOG(trace,
              "Removing NetworkPolicyHosts for policy {} in delta onConfigUpdate() version {}", nid,
              system_version_info);
    to_remove.insert(nid);
  }
  for (const auto& resource : added_resources) {
    const auto& config = dynamic_cast<const cilium::NetworkPolicyHosts&>(resource.get().resource());
    to_remove.insert(config.policy());
  }
  newmap.remove(to_remove);

  for (const auto& resource : added_resources) {
    const auto& config = dynamic_cast<const cilium::NetworkPolicyHosts&>(resource.get().resource());
    ENVOY_LOG(trace,
              "Received NetworkPolicyHosts for policy {} in delta onConfigUpdate() version {}",
              config.policy(), system_version_info);
    insertHosts(newmap, config);
  }

  // Assign the new map to all threads. The slot keeps the callback for the lifetime of the slot
  // (it is replayed on worker threads registered later), so it must not capture a shared pointer
  // to 'this': that would form a reference cycle through tls_ and leak the map.
  auto snapshot = std::make_shared<ThreadLocalHostMap>(std::move(newmap));
  tls_->set([snapshot](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    ENVOY_LOG(trace, "PolicyHostMap: Assigning new map");
    return snapshot;
  });
  logmaps("delta onConfigUpdate");
  accepted_stream_generation_ = stream_generation;
  stats_.update_success_.inc();
  return absl::OkStatus();
}

absl::Status
PolicyHostMap::onConfigUpdate(const std::vector<Envoy::Config::DecodedResourceRef>& resources,
                              const std::string& version_info) {
  ENVOY_LOG(debug, "PolicyHostMap::onConfigUpdate({}), {} resources, version: {}", name_,
            resources.size(), version_info);

  HostMapBuilder newmap;

  for (const auto& resource : resources) {
    const auto& config = dynamic_cast<const cilium::NetworkPolicyHosts&>(resource.get().resource());
    ENVOY_LOG(trace,
              "Received NetworkPolicyHosts for policy {} in onConfigUpdate() "
              "version {}",
              config.policy(), version_info);
    insertHosts(newmap, config);
  }

  // Assign the new map to all threads. The slot keeps the callback for the lifetime of the slot
  // (it is replayed on worker threads registered later), so it must not capture a shared pointer
  // to 'this': that would form a reference cycle through tls_ and leak the map.
  auto snapshot = std::make_shared<ThreadLocalHostMap>(std::move(newmap));
  tls_->set([snapshot](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    ENVOY_LOG(trace, "PolicyHostMap: Assigning new map");
    return snapshot;
  });
  logmaps("onConfigUpdate");
  accepted_stream_generation_ = streamGeneration();
  stats_.update_success_.inc();
  return absl::OkStatus();
}

} // namespace Cilium
} // namespace Envoy
