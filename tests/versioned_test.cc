#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <random>
#include <ranges>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "source/common/common/lock_guard.h"
#include "source/common/common/thread.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "cilium/versioned.h"

// NOLINT(namespace-envoy)
namespace {

class TrackedValue : public VersionedNode<TrackedValue> {
public:
  explicit TrackedValue(int id) : TrackedValue(id, id) {}

  TrackedValue(int key_id, int generation)
      : key_id_(key_id), generation_(generation), unique_id_(next_unique_id_++) {
    ++constructed_count_;
    ++live_count_;
  }

  ~TrackedValue() {
    ++destroyed_count_;
    --live_count_;
    ++destroyed_by_id_[generation_];
  }

  int id() const { return generation_; }
  int keyId() const { return key_id_; }
  int generation() const { return generation_; }
  uint64_t uniqueId() const { return unique_id_; }

  static void resetCounters() {
    constructed_count_ = 0;
    destroyed_count_ = 0;
    live_count_ = 0;
    destroyed_by_id_.clear();
    next_unique_id_ = 1;
  }

  static int constructedCount() { return constructed_count_; }
  static int destroyedCount() { return destroyed_count_; }
  static int liveCount() { return live_count_; }

  static int destroyedCountFor(int id) {
    const auto it = destroyed_by_id_.find(id);
    return it == destroyed_by_id_.end() ? 0 : it->second;
  }

private:
  int key_id_;
  int generation_;
  uint64_t unique_id_;

  static inline int constructed_count_ = 0;
  static inline int destroyed_count_ = 0;
  static inline int live_count_ = 0;
  static inline uint64_t next_unique_id_ = 1;
  static inline std::map<int, int> destroyed_by_id_;
};

using TrackedHandle = VersionedHandle<TrackedValue>;
using TrackedDeferredDeletion = DeferredDeletion<TrackedValue>;
using TrackedMap = VersionedMap<std::string, TrackedValue>;
using TrackedAccess = VersionedTestAccess<std::string, TrackedValue>;

const TrackedValue* activeValue(const TrackedMap& map, const std::string& key,
                                uint64_t version = versionMax) {
  auto handle = map.find(key);
  return handle != nullptr ? handle->get(version) : nullptr;
}

struct PublishedHandles {
  uint64_t snapshot_id;
  uint64_t version;
  std::vector<std::pair<std::string, TrackedHandle>> handles;
};

struct ObservedNode {
  const void* node;
  const void* next;
  const TrackedValue* value;
  uint64_t add_version;
  uint64_t remove_version;
};

enum class ValidationMode {
  StrictConsistentView,
  ConcurrentSafeInvisibleTail,
};

std::string describeValue(const TrackedValue* value) {
  if (value == nullptr) {
    return "nullptr";
  }
  return testing::PrintToString(
      std::make_tuple(value->keyId(), value->generation(), value->uniqueId()));
}

std::string describeObservedChain(const std::vector<ObservedNode>& nodes) {
  std::ostringstream out;
  for (size_t i = 0; i < nodes.size(); ++i) {
    if (i > 0) {
      out << " -> ";
    }
    const auto& node = nodes[i];
    out << "{node=" << node.node << ", next=" << node.next
        << ", value=" << describeValue(node.value) << ", add=" << node.add_version
        << ", remove=" << node.remove_version << "}";
  }
  if (nodes.empty()) {
    out << "<empty>";
  }
  return out.str();
}

std::string validateTraversalAtVersion(const std::string& label,
                                       const VersionedNode<TrackedValue>* initial_head,
                                       uint64_t version, ValidationMode mode,
                                       const TrackedValue* expected = nullptr,
                                       const void* handle = nullptr) {
  const bool require_consistent_view = mode == ValidationMode::StrictConsistentView;
  const TrackedValue* visible_value = nullptr;
  size_t visible_count = 0;
  uint64_t previous_add_version = versionNotRemoved;
  bool in_invisible_tail = false;
  absl::flat_hash_map<const void*, uint64_t> visited_nodes;
  std::vector<ObservedNode> observed_nodes;
  for (const auto* node = initial_head; node != nullptr;) {
    const auto* next = TrackedAccess::next(node);
    observed_nodes.push_back(ObservedNode{node, next, TrackedAccess::value(node),
                                          TrackedAccess::addVersion(node),
                                          TrackedAccess::removeVersion(node)});
    const auto add_version = observed_nodes.back().add_version;
    const auto [visited_it, inserted] = visited_nodes.emplace(node, add_version);
    if (!inserted) {
      if (visited_it->second == add_version) {
        return "cycle detected for '" + label + "' at version " + std::to_string(version) +
               " handle=" + testing::PrintToString(handle) +
               " initial_head=" + testing::PrintToString(initial_head) +
               " chain=" + describeObservedChain(observed_nodes);
      }
      visited_it->second = add_version;
    }

    const auto remove_version = observed_nodes.back().remove_version;
    if (add_version >= versionNotRemoved) {
      return "unpublished node observed for '" + label + "' at version " + std::to_string(version) +
             " handle=" + testing::PrintToString(handle) +
             " initial_head=" + testing::PrintToString(initial_head) +
             " chain=" + describeObservedChain(observed_nodes);
    }
    if ((require_consistent_view || !in_invisible_tail) && add_version > previous_add_version) {
      return "add_version increased while following next links for '" + label + "' at version " +
             std::to_string(version) + " handle=" + testing::PrintToString(handle) +
             " initial_head=" + testing::PrintToString(initial_head) +
             " previous_add=" + std::to_string(previous_add_version) +
             " current_add=" + std::to_string(add_version) +
             " chain=" + describeObservedChain(observed_nodes);
    }
    if (remove_version < versionNotRemoved && add_version > remove_version) {
      return "invalid node visibility window for '" + label + "' at version " +
             std::to_string(version) + " handle=" + testing::PrintToString(handle) +
             " initial_head=" + testing::PrintToString(initial_head) +
             " chain=" + describeObservedChain(observed_nodes);
    }

    if (add_version <= version && version < remove_version) {
      ++visible_count;
      visible_value = TrackedAccess::value(node);
      if (require_consistent_view && visible_count > 1) {
        return "multiple visible nodes at version " + std::to_string(version) + " for '" + label +
               "' handle=" + testing::PrintToString(handle) +
               " initial_head=" + testing::PrintToString(initial_head) +
               " chain=" + describeObservedChain(observed_nodes);
      }
    }
    // Stale nodes may still be reached by a traversal that began before unlinking. They retain
    // their read links and remain alive until the next grace period.
    if (!require_consistent_view && in_invisible_tail &&
        TrackedAccess::isVisibleInVersion(node, version)) {
      return "visible node observed after entering invisible tail for '" + label + "' at version " +
             std::to_string(version) + " handle=" + testing::PrintToString(handle) +
             " initial_head=" + testing::PrintToString(initial_head) +
             " chain=" + describeObservedChain(observed_nodes);
    }
    if (!TrackedAccess::isVisibleInVersion(node, version) &&
        TrackedAccess::addVersion(node) <= version) {
      in_invisible_tail = true;
    }
    previous_add_version = add_version;
    node = next;
  }

  if (require_consistent_view && expected != visible_value) {
    return "handle->get mismatch for '" + label + "' at version " + std::to_string(version) +
           " handle=" + testing::PrintToString(handle) +
           " initial_head=" + testing::PrintToString(initial_head) +
           " expected=" + describeValue(expected) + ", traversed=" + describeValue(visible_value) +
           ", chain=" + describeObservedChain(observed_nodes);
  }

  return "";
}

std::string validateHandleAtVersion(const std::string& label, const TrackedHandle& handle,
                                    uint64_t version,
                                    ValidationMode mode = ValidationMode::StrictConsistentView) {
  if (handle == nullptr) {
    return "snapshot contains null handle for '" + label + "'";
  }

  return validateTraversalAtVersion(
      label, TrackedAccess::head(handle), version, mode,
      mode == ValidationMode::StrictConsistentView ? handle->get(version) : nullptr, handle.get());
}

std::string
validateNodeAtVersion(const std::string& label, const VersionedNode<TrackedValue>* node,
                      uint64_t version,
                      ValidationMode mode = ValidationMode::ConcurrentSafeInvisibleTail) {
  if (node == nullptr) {
    return "null node supplied for '" + label + "'";
  }
  return validateTraversalAtVersion(label, node, version, mode);
}

std::string
validatePublishedSnapshotAtVersion(const PublishedHandles& snapshot, uint64_t version,
                                   ValidationMode mode = ValidationMode::StrictConsistentView) {
  for (const auto& [label, handle] : snapshot.handles) {
    auto error = validateHandleAtVersion(label, handle, version, mode);
    if (!error.empty()) {
      return error;
    }
  }
  return "";
}

std::string validatePublishedSnapshot(const PublishedHandles& snapshot) {
  return validatePublishedSnapshotAtVersion(snapshot, snapshot.version);
}

std::shared_ptr<const PublishedHandles> makePublishedHandles(const TrackedMap& map,
                                                             uint64_t snapshot_id = 0) {
  auto snapshot = std::make_shared<PublishedHandles>();
  snapshot->snapshot_id = snapshot_id;
  snapshot->version = map.getVersion();

  absl::flat_hash_set<const void*> seen_handles;
  for (const auto& [key, handle] : TrackedAccess::entries(map)) {
    if (handle != nullptr && seen_handles.insert(handle.get()).second) {
      snapshot->handles.emplace_back(key, handle);
    }
  }
  size_t dirty_index = 0;
  for (const auto& handle : TrackedAccess::dirtyValues(map)) {
    if (handle != nullptr && seen_handles.insert(handle.get()).second) {
      snapshot->handles.emplace_back("dirty:" + std::to_string(dirty_index++), handle);
    }
  }

  return snapshot;
}

class VersionedTest : public testing::Test {
protected:
  void SetUp() override { TrackedValue::resetCounters(); }

  void TearDown() override {
    EXPECT_EQ(TrackedValue::liveCount(), 0);
    EXPECT_EQ(TrackedValue::constructedCount(), TrackedValue::destroyedCount());
  }
};

TEST_F(VersionedTest, VersionedValueFirstInsertedValueIsVisibleInPublishedVersion) {
  VersionedValue<TrackedValue> value;

  value.set(1, new TrackedValue(1));

  EXPECT_EQ(value.get(0), nullptr);
  ASSERT_NE(value.get(1), nullptr);
  EXPECT_EQ(value.get(1)->id(), 1);
}

TEST_F(VersionedTest, VersionedValueNewerValueShadowsOlderValueFromNewVersionOnward) {
  VersionedValue<TrackedValue> value;

  value.set(1, new TrackedValue(1));
  value.set(2, new TrackedValue(2));

  ASSERT_NE(value.get(1), nullptr);
  EXPECT_EQ(value.get(1)->id(), 1);
  ASSERT_NE(value.get(2), nullptr);
  EXPECT_EQ(value.get(2)->id(), 2);
  EXPECT_EQ(TrackedValue::liveCount(), 2);
}

TEST_F(VersionedTest, VersionedValueClearHidesOnlyFromThatVersionOnward) {
  VersionedValue<TrackedValue> value;

  value.set(1, new TrackedValue(1));
  value.clear(2);

  ASSERT_NE(value.get(1), nullptr);
  EXPECT_EQ(value.get(1)->id(), 1);
  EXPECT_EQ(value.get(2), nullptr);
}

TEST_F(VersionedTest, VersionedValueGcDefersDeletionUntilBatchDestruction) {
  VersionedValue<TrackedValue> value;

  value.set(1, new TrackedValue(1));
  value.set(2, new TrackedValue(2));

  EXPECT_EQ(TrackedValue::liveCount(), 2);

  {
    TrackedDeferredDeletion deferred;
    EXPECT_FALSE(value.gcForVersion(1, deferred));

    EXPECT_TRUE(deferred.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 2);
    EXPECT_EQ(TrackedValue::destroyedCountFor(1), 0);
    ASSERT_NE(value.get(1), nullptr);
    EXPECT_EQ(value.get(1)->id(), 1);
    ASSERT_NE(value.get(2), nullptr);
    EXPECT_EQ(value.get(2)->id(), 2);
  }

  {
    TrackedDeferredDeletion deferred;
    EXPECT_TRUE(value.gcForVersion(2, deferred));

    EXPECT_FALSE(deferred.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 2);
    EXPECT_EQ(TrackedValue::destroyedCountFor(1), 0);
    ASSERT_NE(value.get(2), nullptr);
    EXPECT_EQ(value.get(2)->id(), 2);
  }

  EXPECT_EQ(TrackedValue::liveCount(), 1);
  EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);
  ASSERT_NE(value.get(2), nullptr);
  EXPECT_EQ(value.get(2)->id(), 2);
}

TEST_F(VersionedTest, DeferredDeletionMoveTransfersDeletionOwnership) {
  VersionedValue<TrackedValue> value;

  value.set(1, new TrackedValue(1));
  value.set(2, new TrackedValue(2));

  TrackedDeferredDeletion deferred;
  EXPECT_TRUE(value.gcForVersion(2, deferred));
  EXPECT_FALSE(deferred.empty());
  EXPECT_EQ(TrackedValue::liveCount(), 2);

  {
    TrackedDeferredDeletion moved = std::move(deferred);
    EXPECT_FALSE(moved.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 2);
  }

  EXPECT_EQ(TrackedValue::liveCount(), 1);
  EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);
}

TEST_F(VersionedTest, FirstPhaseGcKeepsCurrentAndHistoricalLookupsMemorySafe) {
  TrackedMap map;

  map.prepareNextVersion();
  auto handle = map.insert("a", new TrackedValue(1));
  const auto version1 = map.publishNextVersion();

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(2));
  const auto version2 = map.publishNextVersion();

  ASSERT_NE(handle, nullptr);

  {
    auto deferred = map.gc(version2);
    EXPECT_FALSE(deferred.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 2);
    EXPECT_EQ(validateHandleAtVersion("a", handle, version1), "");
    EXPECT_EQ(validateHandleAtVersion("a", handle, version2), "");
  }

  EXPECT_EQ(TrackedValue::liveCount(), 1);
  EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);
}

TEST_F(VersionedTest, ConcurrentValidatorAcceptsRetiredNodeTraversal) {
  TrackedMap map;

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(1, 1));
  map.insert("b", new TrackedValue(2, 1));
  map.publishNextVersion();

  auto handle_a = map.find("a");
  auto handle_b = map.find("b");
  ASSERT_NE(handle_a, nullptr);
  ASSERT_NE(handle_b, nullptr);

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(1, 2));
  map.insert("b", new TrackedValue(2, 2));
  const auto version2 = map.publishNextVersion();

  const auto* stale_a = TrackedAccess::next(TrackedAccess::head(handle_a));
  const auto* stale_b = TrackedAccess::next(TrackedAccess::head(handle_b));
  ASSERT_NE(stale_a, nullptr);
  ASSERT_NE(stale_b, nullptr);

  {
    auto deferred = map.gc(version2);
    EXPECT_FALSE(deferred.empty());

    EXPECT_EQ(validateHandleAtVersion("a", handle_a, version2), "");
    EXPECT_EQ(validateHandleAtVersion("b", handle_b, version2), "");
    EXPECT_EQ(validateNodeAtVersion("stale-a", stale_a, version2), "");
    EXPECT_EQ(validateNodeAtVersion("stale-b", stale_b, version2), "");
  }
}

TEST_F(VersionedTest, VersionedMapGcRetainsDirtyHandleUntilAllFutureRemovalsAreReclaimed) {
  TrackedMap map;

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(1));
  map.publishNextVersion();

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(2));
  const auto version2 = map.publishNextVersion();

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(3));
  const auto version3 = map.publishNextVersion();

  EXPECT_EQ(TrackedValue::liveCount(), 3);

  {
    auto deferred = map.gc(version2);

    EXPECT_FALSE(deferred.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 3);
    EXPECT_EQ(TrackedValue::destroyedCountFor(1), 0);
    EXPECT_EQ(TrackedValue::destroyedCountFor(2), 0);
    ASSERT_NE(activeValue(map, "a", version2), nullptr);
    EXPECT_EQ(activeValue(map, "a", version2)->id(), 2);
    ASSERT_NE(activeValue(map, "a", version3), nullptr);
    EXPECT_EQ(activeValue(map, "a", version3)->id(), 3);
  }

  EXPECT_EQ(TrackedValue::liveCount(), 2);
  EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);

  {
    auto deferred = map.gc(version3);

    EXPECT_FALSE(deferred.empty());
    EXPECT_EQ(TrackedValue::liveCount(), 2);
    EXPECT_EQ(TrackedValue::destroyedCountFor(2), 0);
    ASSERT_NE(activeValue(map, "a", version3), nullptr);
    EXPECT_EQ(activeValue(map, "a", version3)->id(), 3);
  }

  EXPECT_EQ(TrackedValue::liveCount(), 1);
  EXPECT_EQ(TrackedValue::destroyedCountFor(2), 1);
  ASSERT_NE(activeValue(map, "a", version3), nullptr);
  EXPECT_EQ(activeValue(map, "a", version3)->id(), 3);
}

TEST_F(VersionedTest, VersionedMapVersionStartsAtMin) {
  TrackedMap map;

  EXPECT_EQ(map.getVersion(), versionMin);
}

TEST_F(VersionedTest, VersionedMapPublishWithNoPendingChangesReturnsZero) {
  TrackedMap map;

  EXPECT_EQ(map.publishNextVersion(), 0);
  EXPECT_EQ(map.getVersion(), versionMin);

  map.prepareNextVersion();

  EXPECT_EQ(map.publishNextVersion(), 0);
  EXPECT_EQ(map.getVersion(), versionMin);
}

TEST_F(VersionedTest, VersionedMapClearAllPreservesPublishedReadsUntilPublication) {
  TrackedMap map;
  map.prepareNextVersion();
  auto first = map.insert("first", new TrackedValue(1));
  auto second = map.insert("second", new TrackedValue(2));
  const auto accepted_version = map.publishNextVersion();

  const auto next_version = map.prepareNextVersion();
  map.clear();
  EXPECT_EQ(first->get(next_version), nullptr);
  EXPECT_EQ(second->get(next_version), nullptr);
  EXPECT_EQ(first->get(accepted_version)->id(), 1);
  EXPECT_EQ(second->get(accepted_version)->id(), 2);

  EXPECT_EQ(map.publishNextVersion(), next_version);
  EXPECT_EQ(map.find("first"), nullptr);
  EXPECT_EQ(map.find("second"), nullptr);
  EXPECT_EQ(first->get(next_version), nullptr);
  EXPECT_EQ(second->get(next_version), nullptr);
}

TEST_F(VersionedTest, VersionedMapClearMissingKeyIsNoOp) {
  TrackedMap map;

  map.prepareNextVersion();
  map.clear("missing");

  EXPECT_EQ(map.publishNextVersion(), 0);
  EXPECT_EQ(map.getVersion(), versionMin);
  EXPECT_EQ(TrackedValue::liveCount(), 0);
}

TEST_F(VersionedTest, VersionedMapSnapshotsIsolateKeysAndVersions) {
  TrackedMap map;

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(1));
  map.insert("b", new TrackedValue(10));
  auto published_version = map.publishNextVersion();
  const auto version1 = map.getVersion();
  map.gc(published_version);

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(2));
  published_version = map.publishNextVersion();
  const auto version2 = map.getVersion();

  ASSERT_NE(activeValue(map, "a", version1), nullptr);
  EXPECT_EQ(activeValue(map, "a", version1)->id(), 1);
  ASSERT_NE(activeValue(map, "a", version2), nullptr);
  EXPECT_EQ(activeValue(map, "a", version2)->id(), 2);
  ASSERT_NE(activeValue(map, "b", version1), nullptr);
  EXPECT_EQ(activeValue(map, "b", version1)->id(), 10);
  ASSERT_NE(activeValue(map, "b", version2), nullptr);
  EXPECT_EQ(activeValue(map, "b", version2)->id(), 10);

  map.gc(published_version);
}

TEST_F(VersionedTest, VersionedMapActiveUpdateReusesStableHandle) {
  TrackedMap map;

  map.prepareNextVersion();
  auto handle = map.insert("a", new TrackedValue(1));
  const auto version1 = map.publishNextVersion();

  ASSERT_NE(handle, nullptr);
  ASSERT_EQ(map.find("a"), handle);
  ASSERT_NE(handle->get(version1), nullptr);
  EXPECT_EQ(handle->get(version1)->id(), 1);

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(2));
  const auto version2 = map.publishNextVersion();

  ASSERT_EQ(map.find("a"), handle);
  ASSERT_NE(handle->get(version1), nullptr);
  EXPECT_EQ(handle->get(version1)->id(), 1);
  ASSERT_NE(handle->get(version2), nullptr);
  EXPECT_EQ(handle->get(version2)->id(), 2);

  map.gc(version2);
}

TEST_F(VersionedTest, VersionedMapClearAndReinsertSameKeyBeforePublishReusesStableHandle) {
  TrackedMap map;

  map.prepareNextVersion();
  auto handle = map.insert("a", new TrackedValue(1));
  const auto version1 = map.publishNextVersion();

  ASSERT_NE(handle, nullptr);
  ASSERT_EQ(map.find("a"), handle);
  ASSERT_NE(handle->get(version1), nullptr);
  EXPECT_EQ(handle->get(version1)->id(), 1);

  map.prepareNextVersion();
  map.clear("a");
  map.insert("a", new TrackedValue(2));
  const auto version2 = map.publishNextVersion();

  ASSERT_EQ(map.find("a"), handle);
  ASSERT_NE(handle->get(version1), nullptr);
  EXPECT_EQ(handle->get(version1)->id(), 1);
  ASSERT_NE(handle->get(version2), nullptr);
  EXPECT_EQ(handle->get(version2)->id(), 2);

  map.gc(version2);
}

TEST_F(VersionedTest, VersionedMapRemovedHandleStaysEmptyAfterSameNameReAdd) {
  TrackedMap map;

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(1));
  map.publishNextVersion();

  auto old_handle = map.find("a");
  ASSERT_NE(old_handle, nullptr);

  map.prepareNextVersion();
  map.clear("a");
  const auto version2 = map.publishNextVersion();
  map.gc(version2);

  EXPECT_EQ(map.find("a"), nullptr);
  EXPECT_EQ(old_handle->get(version2), nullptr);

  map.prepareNextVersion();
  map.insert("a", new TrackedValue(2));
  const auto version3 = map.publishNextVersion();

  auto new_handle = map.find("a");
  ASSERT_NE(new_handle, nullptr);
  EXPECT_NE(new_handle, old_handle);
  ASSERT_NE(new_handle->get(version3), nullptr);
  EXPECT_EQ(new_handle->get(version3)->id(), 2);
  EXPECT_EQ(old_handle->get(version3), nullptr);
  map.gc(version3);
}

TEST_F(VersionedTest, VersionedMapValidatorsAcceptStablePublishedSnapshots) {
  TrackedMap map;
  std::array<int, 32> generations{};

  auto next_value = [&](int key_id) { return new TrackedValue(key_id, ++generations[key_id]); };
  auto expect_snapshot_valid = [&](const std::string& phase) {
    auto snapshot = makePublishedHandles(map);
    EXPECT_EQ(validatePublishedSnapshot(*snapshot), "") << phase;
  };

  map.prepareNextVersion();
  map.insert("key-10", next_value(10));
  map.insert("key-11", next_value(11));
  const auto version1 = map.publishNextVersion();
  ASSERT_EQ(version1, 1);
  expect_snapshot_valid("after initial publish");

  // Exercise same-version churn on one handle: update, clear, and re-add in one transaction.
  map.prepareNextVersion();
  map.insert("key-10", next_value(10)); // generation 2
  map.clear("key-10");
  map.insert("key-10", next_value(10)); // generation 3
  const auto version2 = map.publishNextVersion();
  ASSERT_EQ(version2, 2);
  expect_snapshot_valid("after same-version clear and re-add publish");

  // Exercise both the post-unlink/pre-deletion state and the stable post-deletion state.
  {
    auto deferred = map.gc(version2);
    EXPECT_FALSE(deferred.empty());
    expect_snapshot_valid("after first-phase gc of same-version churn publish");
  }
  expect_snapshot_valid("after deferred deletion of same-version churn publish");

  map.prepareNextVersion();
  map.clear("key-11");
  map.insert("key-12", next_value(12));
  const auto version3 = map.publishNextVersion();
  ASSERT_EQ(version3, 3);
  expect_snapshot_valid("after mixed clear and insert publish");

  {
    auto deferred = map.gc(version3);
    expect_snapshot_valid("after first-phase final gc");
  }
  expect_snapshot_valid("after final deferred deletion");
}

TEST_F(VersionedTest, VersionedMapChaosConcurrentReadersAndWriter) {
  TrackedMap map;

  constexpr size_t k_reader_count = 4;
  constexpr int k_key_count = 32;
  constexpr int k_initial_key_count = 16;
  constexpr int k_max_ops_per_transaction = 8;
  constexpr int k_transaction_count = 2000;
  constexpr uint32_t k_seed = 1337;

  std::array<std::string, k_key_count> key_names;
  std::array<int, k_key_count> generations{};
  for (int i = 0; i < k_key_count; ++i) {
    key_names[i] = "key-" + std::to_string(i);
  }

  auto next_value = [&](int key_id) { return new TrackedValue(key_id, ++generations[key_id]); };

  map.prepareNextVersion();
  for (int i = 0; i < k_initial_key_count; ++i) {
    map.insert(key_names[i], next_value(i));
  }
  auto published_version = map.publishNextVersion();
  ASSERT_GT(published_version, 0);

  uint64_t next_snapshot_id = 1;
  std::shared_ptr<const PublishedHandles> published_snapshot_owner =
      makePublishedHandles(map, next_snapshot_id++);
  std::shared_ptr<const PublishedHandles> previous_snapshot_owner;
  std::atomic<const PublishedHandles*> published_snapshot{published_snapshot_owner.get()};
  std::array<std::atomic<uint64_t>, k_reader_count> reader_quiesced_versions;
  std::array<std::atomic<uint64_t>, k_reader_count> reader_snapshot_ids;
  for (auto& reader_version : reader_quiesced_versions) {
    reader_version.store(versionMin, std::memory_order_relaxed);
  }
  for (auto& reader_snapshot_id : reader_snapshot_ids) {
    reader_snapshot_id.store(0, std::memory_order_relaxed);
  }

  std::atomic<bool> stop{false};
  std::atomic<bool> failed{false};
  Envoy::Thread::MutexBasicLockable failure_mutex;
  std::string failure_message;
  Envoy::Thread::MutexBasicLockable history_mutex;
  std::vector<std::string> recent_history;

  auto record_failure = [&](const std::string& message) {
    bool expected = false;
    if (failed.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
      Envoy::Thread::LockGuard lock(failure_mutex);
      failure_message = message;
    }
  };

  auto record_history = [&](std::string message) {
    Envoy::Thread::LockGuard lock(history_mutex);
    recent_history.push_back(std::move(message));
    constexpr size_t k_history_limit = 128;
    if (recent_history.size() > k_history_limit) {
      recent_history.erase(recent_history.begin(),
                           recent_history.begin() + (recent_history.size() - k_history_limit));
    }
  };

  std::vector<std::thread> readers;
  readers.reserve(k_reader_count);
  for (size_t i = 0; i < k_reader_count; ++i) {
    readers.emplace_back([&, i]() {
      while (!stop.load(std::memory_order_acquire)) {
        const auto* snapshot = published_snapshot.load(std::memory_order_acquire);
        if (snapshot == nullptr) {
          continue;
        }
        if (const auto error = validatePublishedSnapshotAtVersion(
                *snapshot, snapshot->version, ValidationMode::ConcurrentSafeInvisibleTail);
            !error.empty()) {
          record_failure("reader " + std::to_string(i) +
                         " snapshot_id=" + std::to_string(snapshot->snapshot_id) + ": " + error);
          break;
        }
        reader_quiesced_versions[i].store(snapshot->version, std::memory_order_release);
        reader_snapshot_ids[i].store(snapshot->snapshot_id, std::memory_order_release);
      }
    });
  }

  auto publish_snapshot = [&]() {
    previous_snapshot_owner = std::move(published_snapshot_owner);
    published_snapshot_owner = makePublishedHandles(map, next_snapshot_id++);
    published_snapshot.store(published_snapshot_owner.get(), std::memory_order_release);
    return published_snapshot_owner;
  };

  auto release_previous_snapshot = [&]() { previous_snapshot_owner.reset(); };

  auto wait_for_readers_to_observe_snapshot =
      [&](const std::shared_ptr<const PublishedHandles>& snapshot) {
        while (!failed.load(std::memory_order_acquire)) {
          bool all_quiesced = true;
          for (size_t i = 0; i < k_reader_count; ++i) {
            if (reader_quiesced_versions[i].load(std::memory_order_acquire) < snapshot->version ||
                reader_snapshot_ids[i].load(std::memory_order_acquire) < snapshot->snapshot_id) {
              all_quiesced = false;
              break;
            }
          }
          if (all_quiesced) {
            return true;
          }
          std::this_thread::yield();
        }
        return false;
      };

  auto run_deferred_gc = [&](uint64_t version) {
    record_history("gc phase1 " + std::to_string(version));
    auto deferred = map.gc(version);
    if (deferred.empty()) {
      return true;
    }

    const auto post_gc_snapshot = publish_snapshot();
    if (!wait_for_readers_to_observe_snapshot(post_gc_snapshot)) {
      return false;
    }
    release_previous_snapshot();
    record_history("gc phase2 " + std::to_string(version));
    return true;
  };

  auto build_active_set = [&]() {
    std::array<bool, k_key_count> active{};
    for (int i = 0; i < k_key_count; ++i) {
      active[i] = map.find(key_names[i]) != nullptr;
    }
    return active;
  };

  auto random_matching_key = [&](std::minstd_rand& rng, const std::array<bool, k_key_count>& active,
                                 bool want_active) {
    std::vector<int> candidates;
    candidates.reserve(k_key_count);
    for (int i = 0; i < k_key_count; ++i) {
      if (active[i] == want_active) {
        candidates.push_back(i);
      }
    }
    if (candidates.empty()) {
      return -1;
    }
    return candidates[rng() % candidates.size()];
  };

  std::minstd_rand rng(k_seed);
  uint64_t transaction_index = 0;
  while (transaction_index < k_transaction_count && !failed.load(std::memory_order_acquire)) {
    auto active = build_active_set();
    const auto next_version = map.prepareNextVersion();
    ++transaction_index;
    record_history("tx " + std::to_string(transaction_index) +
                   " prepare next=" + std::to_string(next_version));

    const int op_count = 1 + (rng() % k_max_ops_per_transaction);
    for (int op_index = 0; op_index < op_count; ++op_index) {
      const bool has_active = std::ranges::any_of(active, [](bool is_active) { return is_active; });
      const bool has_absent =
          std::ranges::any_of(active, [](bool is_active) { return !is_active; });

      std::vector<int> available_ops;
      if (has_active) {
        available_ops.push_back(0); // update existing
        available_ops.push_back(1); // clear existing
        available_ops.push_back(3); // clear and re-add
      }
      if (has_absent) {
        available_ops.push_back(2); // insert absent
      }
      ASSERT_FALSE(available_ops.empty());

      switch (available_ops[rng() % available_ops.size()]) {
      case 0: {
        const int key_id = random_matching_key(rng, active, true);
        ASSERT_GE(key_id, 0);
        record_history("tx " + std::to_string(transaction_index) + " op " +
                       std::to_string(op_index) + ": update " + key_names[key_id] + " -> gen " +
                       std::to_string(generations[key_id] + 1));
        map.insert(key_names[key_id], next_value(key_id));
        break;
      }
      case 1: {
        const int key_id = random_matching_key(rng, active, true);
        ASSERT_GE(key_id, 0);
        record_history("tx " + std::to_string(transaction_index) + " op " +
                       std::to_string(op_index) + ": clear " + key_names[key_id]);
        map.clear(key_names[key_id]);
        active[key_id] = false;
        break;
      }
      case 2: {
        const int key_id = random_matching_key(rng, active, false);
        ASSERT_GE(key_id, 0);
        record_history("tx " + std::to_string(transaction_index) + " op " +
                       std::to_string(op_index) + ": insert " + key_names[key_id] + " -> gen " +
                       std::to_string(generations[key_id] + 1));
        map.insert(key_names[key_id], next_value(key_id));
        active[key_id] = true;
        break;
      }
      case 3: {
        const int key_id = random_matching_key(rng, active, true);
        ASSERT_GE(key_id, 0);
        record_history("tx " + std::to_string(transaction_index) + " op " +
                       std::to_string(op_index) + ": clear+insert " + key_names[key_id] +
                       " -> gen " + std::to_string(generations[key_id] + 1));
        map.clear(key_names[key_id]);
        map.insert(key_names[key_id], next_value(key_id));
        active[key_id] = true;
        break;
      }
      default:
        FAIL() << "unexpected operation";
      }
    }

    published_version = map.publishNextVersion();
    record_history("tx " + std::to_string(transaction_index) + " publish -> " +
                   std::to_string(published_version));
    if (published_version == 0) {
      continue;
    }

    const auto next_snapshot = publish_snapshot();
    if (!wait_for_readers_to_observe_snapshot(next_snapshot)) {
      break;
    }
    release_previous_snapshot();
    if (!run_deferred_gc(published_version)) {
      break;
    }
  }

  if (!failed.load(std::memory_order_acquire)) {
    const auto final_version = map.getVersion();
    const auto final_snapshot = publish_snapshot();
    if (final_version > versionMin) {
      EXPECT_TRUE(wait_for_readers_to_observe_snapshot(final_snapshot));
      release_previous_snapshot();
      if (!failed.load(std::memory_order_acquire)) {
        EXPECT_TRUE(run_deferred_gc(final_version));
      }
    }
  }

  stop.store(true, std::memory_order_release);
  for (auto& reader : readers) {
    reader.join();
  }
  published_snapshot.store(nullptr, std::memory_order_release);
  previous_snapshot_owner.reset();
  published_snapshot_owner.reset();

  if (failed.load(std::memory_order_acquire)) {
    Envoy::Thread::LockGuard lock(failure_mutex);
    std::ostringstream history;
    {
      Envoy::Thread::LockGuard history_lock(history_mutex);
      for (const auto& entry : recent_history) {
        history << "\n  " << entry;
      }
    }
    FAIL() << "seed=" << k_seed << " " << failure_message << "\nrecent history:" << history.str();
  }
}

TEST_F(VersionedTest, VersionedMapGcAndDestructorDeleteValuesExactlyOnce) {
  {
    TrackedMap map;

    map.prepareNextVersion();
    map.insert("a", new TrackedValue(1));
    auto published_version = map.publishNextVersion();
    map.gc(published_version);

    map.prepareNextVersion();
    map.insert("a", new TrackedValue(2));
    published_version = map.publishNextVersion();

    EXPECT_EQ(TrackedValue::liveCount(), 2);

    {
      auto deferred = map.gc(published_version);
      EXPECT_FALSE(deferred.empty());
      EXPECT_EQ(TrackedValue::liveCount(), 2);
      EXPECT_EQ(TrackedValue::destroyedCountFor(1), 0);
      EXPECT_EQ(TrackedValue::destroyedCountFor(2), 0);
    }

    EXPECT_EQ(TrackedValue::liveCount(), 1);
    EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);
    EXPECT_EQ(TrackedValue::destroyedCountFor(2), 0);
  }

  EXPECT_EQ(TrackedValue::liveCount(), 0);
  EXPECT_EQ(TrackedValue::destroyedCountFor(1), 1);
  EXPECT_EQ(TrackedValue::destroyedCountFor(2), 1);
}

} // namespace
