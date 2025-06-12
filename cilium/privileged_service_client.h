#pragma once

#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "envoy/api/os_sys_calls_common.h"

#include "source/common/common/assert.h"
#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/singleton/threadsafe_singleton.h"

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
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
  bool haveCiliumPrivilegedService() const { return isOpen(); }

  ssize_t transact(MessageHeader& req, size_t req_len, const void* data, size_t datalen, int* fd,
                   Response& resp, void* buf = nullptr, size_t buf_size = 0);

  std::atomic<uint32_t> seq_;
  Thread::MutexBasicLockable call_mutex_;

  class Waiter {
  public:
    Waiter() = default;

    ssize_t recvFdMsg(ProtocolClient& client) {
      return size_ = client.recvFdMsg(&resp_, sizeof(resp_), buf_, sizeof(buf_), &fd_);
    }

    // Returns non-zero sequence number after a response has been received.
    uint32_t seq() const { return resp_.hdr_.msg_seq_; }

    // Returns received message type
    MessageType msgType() const { return static_cast<MessageType>(resp_.hdr_.msg_type_); }

    // validate checks that the received sequence number matches the expected one
    // Returns zero if no respnse has yet been received.
    ssize_t validate(uint32_t expected_seq_n) const {
      auto received_seq = seq();
      if (received_seq) {
        RELEASE_ASSERT(received_seq == expected_seq_n,
                       fmt::format("waiter: invalid response sequence: {} != {}", received_seq,
                                   expected_seq_n));
        return size_;
      }
      return 0;
    }

    ssize_t getResponse(Response& resp, void* buf, size_t buf_size, int* fd) const {
      ssize_t size = size_;
      if (size_t(size) > sizeof(resp)) {
        auto copy_size = size_t(size) - sizeof(resp);
        if (copy_size > buf_size) {
          // truncate response
          size -= copy_size - buf_size;
          copy_size = buf_size;
        }
        memcpy(buf, buf_, copy_size); // NOLINT(safe-memcpy)
      }
      resp = resp_;
      if (fd) {
        *fd = fd_;
      }

      return size;
    }

    Waiter& operator=(Waiter& other) {
      size_ = other.size_;
      fd_ = other.fd_;
      resp_ = other.resp_;
      if (size_ > ssize_t(sizeof(resp_))) {
        size_t copy_size = size_t(size_) - sizeof(resp_);
        if (copy_size <= sizeof(buf_)) {
          memcpy(buf_, other.buf_, copy_size); // NOLINT(safe-memcpy)
        }
      }
      return *this;
    }

    void clear() {
      size_ = 0;
      fd_ = -1;
      resp_ = {};
    }

  private:
    ssize_t size_{}; // non-zero after a the response has been received
    int fd_;
    Response resp_;
    char buf_[RESPONSE_BUF_SIZE];
  };

  // waiterReceive is declared as noexcept to guarantee it will return normally, rather than via an
  // exception, if the program continues running. This allows for safe removal of the Waiter from
  // Waiters before the Waiter is destructed.
  ssize_t waiterReceive(Waiter&, uint32_t seq) noexcept;

  using WaitersMap = absl::flat_hash_map<uint32_t, Waiter*>;

  class Waiters {
  public:
    void insert(uint32_t seq, Waiter* waiter) {
      Thread::LockGuard guard(mutex_);
      auto ret = map_.emplace(seq, waiter);
      RELEASE_ASSERT(ret.second, "waiter emplace failed");
    }

    void remove(uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      map_.erase(seq);
    }

    // wait waits for either a response to be received, or be woken up to become a receiver.
    // Returns non-zero if there is a response, zero if the receiver quit.
    ssize_t wait(const Waiter& waiter, uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      while (waiter.seq() == 0 && is_receiver_active_) {
        cond_.wait(mutex_);
      }
      return waiter.validate(seq);
    }

    // wakeUp passes the reveived data to the waiter with sequence number 'seq' and wakes all
    // waiters.
    void wakeUp(Waiter& receiver) {
      {
        Thread::LockGuard guard(mutex_);
        auto seq = receiver.seq();
        auto it = map_.find(receiver.seq());
        RELEASE_ASSERT(it != map_.end(), fmt::format("no waiter found for seq {}", seq));
        // copy received data to the found waiter
        *it->second = receiver;
        // clear the waiter of the current receiver
        receiver.clear();
      }
      cond_.notifyAll();
    }

    // Called when a thread successfully acquires call_mutex_
    // Returns zero if the called should enter the receive loop.
    ssize_t setReceiverActiveIfNoResponse(const Waiter& waiter, uint32_t seq) {
      Thread::LockGuard guard(mutex_);
      if (waiter.seq()) {
        auto size = waiter.validate(seq);
        if (size != 0) {
          return size;
        }
      }
      is_receiver_active_ = true;
      return 0;
    }

    // This is called by the thread that just released the call_mutex_.
    // Wakes up waiters to become the next receiver.
    void signalReceiverOpen() {
      {
        Thread::LockGuard guard(mutex_);
        is_receiver_active_ = false;
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
