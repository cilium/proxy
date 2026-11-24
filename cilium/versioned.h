#pragma once

// NOLINT(namespace-envoy)

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

#include "source/common/common/assert.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

constexpr uint64_t versionMin = 0;
constexpr uint64_t versionMax = std::numeric_limits<uint64_t>::max() - 1;
constexpr uint64_t versionNotRemoved = std::numeric_limits<uint64_t>::max();

// Versioned.h provides a lock-free reader / single-writer versioned-value container,
// based on earlier implementations in OVS (C) and Cilium (Go).
//
// API contract and intended use:
//
// 1. Object model
//    - T is a CRTP node type inheriting from VersionedNode<T>.
//    - VersionedValue<T, R> owns a linked list of historical T nodes, newest first. Inserting a
//      node transfers its ownership to the handle, and GC transfers unlinked nodes to
//      DeferredDeletion.
//    - VersionedReadable<T> exposes only the worker-safe read API: get(version).
//    - VersionedHandle<T, V> is a shared_ptr<const typename V::Readable>, so handles intentionally
//      expose only the readable API to worker/runtime code. Main-thread mutation goes through
//      VersionedMap, which keeps mutable shared_ptr<V> internally.
//    - The optional readable base R allows a handle to expose extra read-only metadata (for
//      example selector names) without exposing VersionedValue mutators.
//
// 2. Threading model
//    - There is exactly one mutator thread: the main thread.
//    - Worker threads may concurrently call VersionedReadable::get(version) and may traverse nodes
//      reached from a handle without additional locking.
//    - Any future cross-thread mutation must still preserve the exclusive-writer rule, e.g. by
//      holding an exclusive lock around all mutation.
//    - VersionedMap's name directory (map_), dirty set, and unpublished batch state are
//      main-thread-only. getVersion() reads an atomic published version; it does not make the
//      directory or mutation methods safe to access from workers.
//
// 3. VersionedMap update flow
//    - Validate and initialize candidates before staging their accepted changes. There is no
//      rollback API; the caller excludes failed candidates before mutating this map.
//    - prepareNextVersion() starts a new unpublished update and returns the candidate version to
//      use for any main-thread lookups against in-flight state.
//    - insert(key, value) reuses the existing stable handle if the key is still present in the
//      main-thread directory; otherwise it creates a fresh handle.
//    - An optional prepared_handle lets the caller bind references before insertion. Replacing a
//      different existing handle requires it to have no value in the candidate version. The map
//      retains the displaced handle for GC.
//    - clear(key) marks the key's current value invisible in the candidate version but does not
//      erase the key from the main-thread directory immediately. clear() does this for every key.
//    - publishNextVersion() publishes all pending changes, removes keys whose handle has no visible
//      value in the published version, and returns the new published version, or 0 if there was
//      nothing to publish.
//    - If other state must become visible with this version, the caller publishes them together
//      through one snapshot. Publishing this map's version alone does not synchronize unrelated
//      state.
//    - find(key) returns the stable readable handle parked under the key in the main-thread
//      directory. It does not itself answer whether the key is visible in any specific version; use
//      handle->get(version) for that.
//
// 4. Stable-handle semantics
//    - Without an explicit prepared_handle, updating an active key writes a new version onto the
//      same stable handle. Clearing and re-adding the same key in one unpublished update also
//      reuses that handle; the caller should compare against the candidate version returned from
//      prepareNextVersion(), not against the currently published version.
//    - Supplying a fresh prepared_handle after clearing the old one starts a new namespace for
//      that key within the same update. References to the old handle remain bound to the old one.
//    - Once a key has been fully removed across a published version boundary, the name disappears
//      from VersionedMap. A later same-name add creates a fresh stable handle.
//    - This is why old published policies can keep using an old cleared handle while refreshed
//      policies bind a new one after a later same-name re-add.
//
// 5. Reader semantics
//    - get(version) walks from the current head and returns the first node visible in the requested
//      version.
//    - The walk stops at the first node that was added before the requested version but is no
//      longer visible there; all remaining nodes are older and therefore already invisible in that
//      version.
//    - Workers use a version obtained from the caller's published state. Staged nodes can already
//      be reachable, but their addition/removal versions preserve reads of the published version.
//    - The returned pointer is borrowed. The caller must hold the handle and protect the read,
//      including any use of that pointer, through its grace-period protocol.
//    - Older versions remain readable until GC reclaims their values. A shared handle alone does
//      not retain every historical value; after GC an older-version lookup may return nullptr.
//      Such lookups remain memory-safe when performed within the protected read scope.
//
// 6. Deferred deletion / grace periods
//    - The caller provides quiescence: readers have finished using the versions and borrowed
//      pointers being retired. The container does not track reader lifetimes itself.
//    - gc(published_version) is only the first GC phase. Call it after readers that could still
//      require earlier versions have quiesced. It unlinks nodes removed at or before that version
//      and returns them in a DeferredDeletion batch.
//    - Nodes removed in later versions remain linked, and their handles stay tracked for future GC.
//    - The returned DeferredDeletion batch must stay alive until all workers have quiesced once
//      more. Destroying the batch performs the actual node deletion.
//    - The production pattern is therefore: publish version N, wait for worker quiescence, call
//      gc(N), then keep the returned DeferredDeletion alive for one more quiescence round.
//
// 7. High-level memory-model rationale
//    - The main thread publishes new list links with 'release' stores to the list node pointers.
//    - Workers traverse with 'acquire' loads from the list node pointers. Each observed link is
//      atomic and publishes the linked node's initialization; a traversal may observe links from
//      different moments rather than one snapshot of the entire chain.
//    - published_version_ is stored with 'release' in publishNextVersion() and loaded with
//      'acquire' by getVersion(), so observing a new version also orders the preceding list and
//      visibility changes. A caller publishing the version through a larger snapshot must provide
//      equivalent ordering. PolicyMapSnapshot does this for policies and their selector version.
//    - remove_version_ uses 'relaxed' atomic loads/stores to avoid data races while readers
//      inspect nodes during staging. Publication orders these visibility changes for the accepted
//      version; link ordering alone does not publish later changes to existing nodes.
//    - Deferred deletion keeps nodes alive for traversals that reached them before unlinking.
//    - Many mutation-side loads/stores are 'relaxed' because mutation is single-threaded on the
//      main thread.
//
// 8. DeferredDeletion implementation detail
//    - DeferredDeletion owns unlinked nodes in a main-thread-only vector of unique_ptr<T>.
//      Their read-side next_ links stay intact until deletion, so a reader that already reached an
//      unlinked node can still continue along the original chain.
//    - Reusing next_ for deletion ownership could make such a traversal miss a visible value.
//      The vector allocates storage only for retired nodes, without adding fields to live nodes.
//    - Map GC uses the dirty-handle count as a capacity hint, reserved on the first retirement.
//    - Moving a batch transfers deletion ownership. Destroying it deletes its nodes, so destruction
//      must wait for the second grace period. Only get(version) is the supported read API.
//
// 9. Test coverage in tests/versioned_test.cc
//    - Value-level tests cover visibility rules, shadowing, clear(), first-phase GC, and
//      deferred deletion ownership/move semantics.
//    - Map-level tests cover version numbering, publish-without-change, insert/update/clear,
//      clear-all visibility, same-handle reuse for active updates and same-update clear+re-add,
//      fresh-handle behavior after published removal, and dirty-handle retention across multiple
//      future GC runs.
//    - Stable validator tests verify consistent published snapshots and post-unlink/pre-deletion
//      states.
//    - A multithreaded chaos test exercises one writer with multiple busy-loop readers, repeated
//      publish/GC cycles, stale-version reads, and traversal safety under deferred deletion.
//
template <typename T> class VersionedReadable;
template <typename T, typename R = VersionedReadable<T>> class VersionedValue;
template <typename T> class DeferredDeletion;
template <typename K, typename T, typename V = VersionedValue<T>> struct VersionedTestAccess;

// VersionedNode is CRTP type on T, T must inherit from VersionedNode<T>
template <typename T> class VersionedNode {
public:
  VersionedNode() : next_(nullptr), remove_version_(versionNotRemoved) {}

private:
  template <typename U> friend class VersionedReadable;
  template <typename U, typename R> friend class VersionedValue;
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;

  bool isUnpublished() const { return add_version_ == versionNotRemoved; }

  void setAddVersion(uint64_t version) {
    ASSERT(version < versionNotRemoved);
    add_version_ = version; // set before published
  }

  void removeInVersion(uint64_t version) {
    remove_version_.store(version, std::memory_order_relaxed);
  }

  bool isVisibleInVersion(uint64_t version) const {
    return add_version_ <= version && version < remove_version_.load(std::memory_order_relaxed);
  }

  bool isAddedBeforeVersion(uint64_t version) const { return add_version_ < version; }

  bool isEventuallyInvisible() const {
    return remove_version_.load(std::memory_order_relaxed) < versionNotRemoved;
  }

  bool isVisibleOnlyBeforeVersion(uint64_t version) const {
    return remove_version_.load(std::memory_order_relaxed) <= version;
  }

  VersionedNode<T>* getNext() const { return next_.load(std::memory_order_acquire); }

  void setNext(VersionedNode<T>* next) { next_.store(next, std::memory_order_release); }

  VersionedNode<T>* getNextProtected() const { return next_.load(std::memory_order_relaxed); }
  std::atomic<VersionedNode<T>*>* getNextP() { return &next_; }

  T* value() { return static_cast<T*>(this); }
  const T* value() const { return static_cast<const T*>(this); }

  std::atomic<VersionedNode<T>*> next_;

  uint64_t add_version_{versionNotRemoved}; // Version object was added in.
  std::atomic<uint64_t> remove_version_;    // Version object is removed in.
};

template <typename T> class VersionedReadable {
public:
  const T* get(uint64_t version) const {
    for (auto node = head_.load(std::memory_order_acquire); node; node = node->getNext()) {
      if (node->isVisibleInVersion(version)) {
        return node->value();
      }
      // stop traversal on first non-visible version that was added before this version, all
      // remaining nodes are already invisible.
      if (node->isAddedBeforeVersion(version)) {
        break;
      }
    }
    return nullptr; // not found
  }

protected:
  VersionedReadable() : head_(nullptr) {}

  template <typename U, typename R> friend class VersionedValue;
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;

  std::atomic<VersionedNode<T>*> head_;
};

// T is the CRTP node type stored in the version chain. R is the read-only interface exposed
// through VersionedHandle: it defaults to VersionedReadable<T>, but callers may provide a richer
// readable base when handles need extra read-side API without exposing the main-thread mutators.
template <typename T, typename R> class VersionedValue : public R {
public:
  using Readable = R;
  using R::head_;

  VersionedValue() = default;

  template <class... Args, typename = std::enable_if_t<std::is_constructible_v<R, Args...>>>
  explicit VersionedValue(Args&&... args) : R(std::forward<Args>(args)...) {}

  ~VersionedValue() {
    VersionedNode<T>* next;
    for (auto node = head_.load(std::memory_order_relaxed); node; node = next) {
      next = node->getNextProtected();
      delete node->value();
    }
  }

  // make all versions invisible starting at "version"
  void clear(uint64_t version) {
    for (auto node = head_.load(std::memory_order_relaxed); node; node = node->getNextProtected()) {
      if (!node->isEventuallyInvisible()) {
        node->removeInVersion(version);
      }
    }
  }

  void set(uint64_t version, VersionedNode<T>* node) {
    // publish a new version that is visible starting at "version"
    ASSERT(node->isUnpublished()); // node not pushed into a list yet
    node->setAddVersion(version);
    node->setNext(head_.load(std::memory_order_relaxed));
    head_.store(node, std::memory_order_release);

    // make all other versions invisible at "version", starting from the first old node.
    for (node = node->getNextProtected(); node; node = node->getNextProtected()) {
      if (node->isVisibleInVersion(version)) {
        node->removeInVersion(version);
      }
    }
  }

  bool empty() const { return head_.load(std::memory_order_relaxed) == nullptr; }

  // Unlink all versions not visible to anyone after the "version" was published and all readers
  // have quiesced, but do not delete them yet. Unlinked nodes are appended to 'deferred' and are
  // only deleted after one more worker-thread quiescence round. Any nodes not yet visible at
  // "version" must not be unlinked.
  // Returns true if there are no future version removals left in this handle after this first
  // phase GC run.
  bool gcForVersion(uint64_t version, DeferredDeletion<T>& deferred) {
    ASSERT(version < versionNotRemoved);
    auto prev = &head_;
    VersionedNode<T>* next;
    bool has_future_gc_work = false;
    for (auto node = head_.load(std::memory_order_relaxed); node; node = next) {
      next = node->getNextProtected();
      if (node->isVisibleOnlyBeforeVersion(version)) {
        if (deferred.nodes_.empty()) {
          deferred.nodes_.reserve(deferred.reserve_hint_);
        }
        deferred.nodes_.emplace_back(node->value());
        // unlink node by pointing prev to next
        prev->store(next, std::memory_order_release);
        // prev stays
        continue;
      }
      if (node->isEventuallyInvisible()) {
        has_future_gc_work = true;
      }
      prev = node->getNextP();
    }
    return !has_future_gc_work;
  }

protected:
  template <typename K, typename U, typename V> friend struct VersionedTestAccess;
};

template <typename T> class DeferredDeletion {
public:
  explicit DeferredDeletion(std::size_t reserve_hint = 0) : reserve_hint_(reserve_hint) {}
  DeferredDeletion(const DeferredDeletion&) = delete;
  DeferredDeletion& operator=(const DeferredDeletion&) = delete;
  DeferredDeletion(DeferredDeletion&&) noexcept = default;
  DeferredDeletion& operator=(DeferredDeletion&&) noexcept = delete;

  bool empty() const { return nodes_.empty(); }

private:
  template <typename U, typename R> friend class VersionedValue;

  std::vector<std::unique_ptr<T>> nodes_;
  std::size_t reserve_hint_;
};

template <typename T, typename V = VersionedValue<T>>
using VersionedHandle = std::shared_ptr<const typename V::Readable>;

// VersionedMap is main-thread / exclusive-writer only: map_, pending_keys_, dirty_values_, and
// all mutation methods are accessed only by the single publishing thread. Worker threads only use
// the published Handle objects and then call the read-only handle API.
template <typename K, typename T, typename V = VersionedValue<T>> class VersionedMap {
public:
  static_assert(std::is_base_of_v<typename V::Readable, V>);
  static_assert(std::is_base_of_v<VersionedReadable<T>, typename V::Readable>);
  using Handle = VersionedHandle<T, V>;

  uint64_t getVersion() const { return published_version_.load(std::memory_order_acquire); }

  Handle find(const K& key) const {
    auto it = map_.find(key);
    if (it != map_.cend()) {
      return it->second;
    }
    return nullptr;
  }

  uint64_t prepareNextVersion() {
    ASSERT(pending_keys_.empty());
    return ++next_version_;
  }

  Handle insert(const K& key, T* value, std::shared_ptr<V> prepared_handle = nullptr) {
    ASSERT(next_version_ > published_version_.load(std::memory_order_relaxed));
    auto [it, inserted] = map_.try_emplace(key);
    if (prepared_handle) {
      if (!inserted && it->second != prepared_handle) {
        // A new namespace may replace a same-name handle cleared in this batch.
        ASSERT(it->second->get(next_version_) == nullptr);
        dirty_values_.emplace(it->second);
      }
      it->second = std::move(prepared_handle);
    } else if (inserted) {
      if constexpr (std::is_constructible_v<V, const K&>) {
        it->second = std::make_shared<V>(key);
      } else {
        it->second = std::make_shared<V>();
      }
    }
    auto& handle = it->second;
    handle->set(next_version_, value);
    pending_keys_.emplace(key);
    return handle;
  }

  void clear(const K& key) {
    ASSERT(next_version_ > published_version_.load(std::memory_order_relaxed));
    auto it = map_.find(key);
    if (it != map_.cend()) {
      it->second->clear(next_version_);
      pending_keys_.emplace(key);
    }
  }

  void clear() {
    ASSERT(next_version_ > published_version_.load(std::memory_order_relaxed));
    for (const auto& [key, handle] : map_) {
      handle->clear(next_version_);
      pending_keys_.emplace(key);
    }
  }

  // returns the newly published version, or 0 if there was nothing to publish
  uint64_t publishNextVersion() {
    auto version = published_version_.load(std::memory_order_relaxed);
    if (next_version_ <= version || pending_keys_.empty()) {
      // No changes; keep the published version.
      next_version_ = version;
      pending_keys_.clear();
      return 0;
    }
    for (const auto& key : pending_keys_) {
      auto it = map_.find(key);
      ASSERT(it != map_.end());
      dirty_values_.emplace(it->second);
      if (it->second->get(next_version_) == nullptr) {
        map_.erase(it);
      }
    }
    published_version_.store(next_version_, std::memory_order_release);
    pending_keys_.clear();
    return next_version_;
  }

  // First phase GC after all readers have quiesced for 'published_version'. This unlinks nodes that
  // are no longer visible and returns them in a deferred-deletion batch that must survive until all
  // readers have quiesced once more before it is destroyed.
  DeferredDeletion<T> gc(uint64_t published_version) {
    DeferredDeletion<T> deferred(dirty_values_.size());
    for (auto it = dirty_values_.begin(); it != dirty_values_.end();) {
      const auto& handle = *it;
      if (handle->gcForVersion(published_version, deferred)) {
        dirty_values_.erase(it++);
        continue;
      }
      ++it;
    }
    return deferred;
  }

private:
  friend struct VersionedTestAccess<K, T, V>;
  using MutableHandle = std::shared_ptr<V>;

  // Persistent published state.
  std::atomic<uint64_t> published_version_{versionMin};
  absl::flat_hash_map<K, MutableHandle> map_;
  absl::flat_hash_set<MutableHandle> dirty_values_;

  // State for the currently prepared unpublished batch.
  // Valid only after prepareNextVersion() and until publishNextVersion().
  // `next_version_` is the candidate version being built, and `pending_keys_`
  // contains the keys touched in that candidate update. The container is reused
  // across updates to avoid repeated allocation churn.
  uint64_t next_version_{versionMin};
  absl::flat_hash_set<K> pending_keys_;
};

template <typename K, typename T, typename V> struct VersionedTestAccess {
  using Map = VersionedMap<K, T, V>;
  using Handle = typename Map::Handle;
  using MutableHandle = typename Map::MutableHandle;
  using Node = VersionedNode<T>;

  static const absl::flat_hash_map<K, MutableHandle>& entries(const Map& map) { return map.map_; }

  static const absl::flat_hash_set<MutableHandle>& dirtyValues(const Map& map) {
    return map.dirty_values_;
  }

  static const Node* head(const Handle& handle) {
    if (handle == nullptr) {
      return nullptr;
    }
    auto value = std::static_pointer_cast<const V>(handle);
    return value->head_.load(std::memory_order_acquire);
  }

  static const Node* next(const Node* node) {
    return node ? node->next_.load(std::memory_order_acquire) : nullptr;
  }

  static const T* value(const Node* node) { return node ? node->value() : nullptr; }

  static uint64_t addVersion(const Node* node) { return node->add_version_; }

  static uint64_t removeVersion(const Node* node) {
    return node->remove_version_.load(std::memory_order_relaxed);
  }

  static bool isVisibleInVersion(const Node* node, uint64_t version) {
    return node && node->isVisibleInVersion(version);
  }
};
