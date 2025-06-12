#pragma once

#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "envoy/api/os_sys_calls_common.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/singleton/threadsafe_singleton.h"

#include "starter/privileged_service_protocol.h"

namespace Envoy {
namespace Cilium {

class Bpf;
class SocketMarkOption;

namespace PrivilegedService {

#define RESPONSE_BUF_SIZE 1024

// ProtocolClient implements the client logic for communicating with the privileged service.
class ProtocolClient : public Protocol, Logger::Loggable<Logger::Id::filter> {
public:
  ProtocolClient();

  // allow access to the classes that need it
  friend class Envoy::Cilium::Bpf;
  friend class Envoy::Cilium::SocketMarkOption;

  // Set a socket option
  Envoy::Api::SysCallIntResult setsockopt(int sockfd, int level, int optname, const void* optval,
                                          socklen_t optlen);

protected:
  // Read-only bpf syscalls
  Envoy::Api::SysCallIntResult bpfOpen(const char* path);
  Envoy::Api::SysCallIntResult bpfLookup(int fd, const void* key, uint32_t key_size, void* value,
                                         uint32_t value_size);

private:
  bool checkPrivilegedService();
  bool haveCiliumPrivilegedService() const { return is_open(); }

  ssize_t transact(MessageHeader& req, size_t req_len, const void* data, size_t datalen, int* fd,
                   Response& resp, void* buf = nullptr, size_t bufsize = 0, bool assert = true);

  std::atomic<uint32_t> seq_;
  Thread::MutexBasicLockable call_mutex_;

  class Waiter {
  public:
    Waiter(Response* resp, void* buf, size_t buf_size, int* fd)
        : resp_(resp), buf_(buf), buf_size_(buf_size), fd_(fd) {
      // zero out response header
      resp_->hdr_ = MessageHeader();
    }

    uint32_t seq() const { return resp_->hdr_.msg_seq_; }
    MessageType msgType() const { return static_cast<MessageType>(resp_->hdr_.msg_type_); }

    ssize_t validate(MessageType expected_msg_type, uint32_t expected_seq_n) const {
      auto received_seq = seq();
      if (received_seq) {
        auto received_type = msgType();
        RELEASE_ASSERT((received_type == expected_msg_type && received_seq == expected_seq_n &&
                        size_ >= ssize_t(sizeof(Response))),
                       fmt::format("waiter: invalid response: seq: {}/{}, type: {}/{}, size: {}",
                                   received_seq, expected_seq_n,
                                   static_cast<uint32_t>(received_type),
                                   static_cast<uint32_t>(expected_msg_type), size_));
        return size_;
      }
      return 0;
    }

    ssize_t updateValue(ssize_t size, void* buf) {
      RELEASE_ASSERT(size != 0, "waiter response with zero size");
      if (size_t(size) > sizeof(Response)) {
        auto copy_size = size_t(size) - sizeof(Response);
        if (copy_size > buf_size_) {
          // truncate response
          size -= copy_size - buf_size_;
          copy_size = buf_size_;
        }
        memcpy(buf_, buf, copy_size); // NOLINT(safe-memcpy)
      }
      return size;
    }

    void update(ssize_t size, Response& resp, void* buf, int* fd) {
      *resp_ = resp;
      *fd_ = *fd;
      size_ = updateValue(size, buf);
    }

  private:
    ssize_t size_{};
    Response* resp_;
    void* buf_;
    size_t buf_size_;
    int* fd_;
  };

  using WaitersMap = absl::flat_hash_map<uint32_t, Waiter*>;

  class Waiters {
  public:
    WaitersMap::iterator insert(uint32_t seq, Waiter* waiter) {
      Thread::LockGuard guard(mutex_);
      auto ret = map_.emplace(seq, waiter);
      RELEASE_ASSERT(ret.second, "waiter emplace failed");
      return ret.first;
    }

    void remove(uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      map_.erase(seq);
    }

    ssize_t wait(const Waiter& waiter, MessageType msg_type, uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      while (waiter.seq() == 0 && is_receiver_active_) {
        cond_.wait(mutex_);
      }
      auto size = waiter.validate(msg_type, seq);
      if (size != 0) {
        // response received, remove the waiter
        map_.erase(seq);
      }
      return size;
    }

    void wakeUp(uint32_t seq, ssize_t size, Response& resp, void* buf, int* fd) {
      {
        Thread::LockGuard guard(mutex_);
        auto it = map_.find(seq);
        RELEASE_ASSERT(it != map_.end(), fmt::format("no waiter found for seq {}", seq));
        it->second->update(size, resp, buf, fd);
      }
      cond_.notifyAll();
    }

    // Called when a thread successfully acquires call_mutex_
    ssize_t setReceiverActiveIfNoResponse(const Waiter& waiter, MessageType msg_type,
                                          uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      if (waiter.seq()) {
        return waiter.validate(msg_type, seq);
      }
      is_receiver_active_ = true;
      return -1;
    }

    // This is called by the thread that just released the call_mutex_.
    void signalReceiverOpen(uint32_t seq) {
      {
        Thread::LockGuard guard(mutex_);
        is_receiver_active_ = false;
        map_.erase(seq);
      }
      cond_.notifyAll();
    }

  private:
    Thread::MutexBasicLockable mutex_;
    Thread::CondVar cond_;
    WaitersMap map_ ABSL_GUARDED_BY(mutex_);
    bool is_receiver_active_ ABSL_GUARDED_BY(mutex_) = false;
  };

  Waiters waiters_;
};

using Singleton = Envoy::ThreadSafeSingleton<ProtocolClient>;

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
