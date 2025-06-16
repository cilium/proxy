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

  // Waiter has space for a response. While placed in the 'waiters_' map, all access to the
  // waiter must happen while holding 'mutex_', except for the designated receiver may
  // access it's own waiter without the mutex.
  class Waiter {
  public:
    Waiter() = default;

    // Returns non-zero sequence number after a response has been received.
    uint32_t seq() const { return resp_.hdr_.msg_seq_; }

    // Returns received message type
    MessageType msgType() const { return static_cast<MessageType>(resp_.hdr_.msg_type_); }

    ssize_t recvFdMsg(ProtocolClient& client) {
      size_ = client.recvFdMsg(&resp_, sizeof(resp_), buf_, sizeof(buf_), &fd_);
      if (size_ >= 0) {
        // Failing release asserts cause an exit and an automated restart. This is the only way
        // to recover from privilaged service failures.
        RELEASE_ASSERT(size_ != 0, "Cilium privileged service closed pipe");
        // Must have enough data to decode the response header
        RELEASE_ASSERT(size_t(size_) >= sizeof(Response),
                       "Cilium privileged service truncated response");
        RELEASE_ASSERT(msgType() == MessageType::TypeResponse,
                       "Cilium privileged service unexpected response type");
      }
      return size_;
    }

    ssize_t getResponse(uint32_t expected_seq_n, Response& resp, void* buf, size_t buf_size,
                        int* fd) const {
      auto received_seq = seq();
      RELEASE_ASSERT(
          received_seq == 0 && size_ <= 0 || received_seq == expected_seq_n,
          fmt::format("waiter: invalid response sequence: {} != {}", received_seq, expected_seq_n));

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
    // 'size_' non-zero after a the response has been received
    ssize_t size_{};
    int fd_;
    Response resp_;
    char buf_[RESPONSE_BUF_SIZE];
  };

  void insert(uint32_t seq, Waiter* waiter) {
    Thread::LockGuard guard(mutex_);
    auto ret = waiters_.emplace(seq, waiter);
    RELEASE_ASSERT(ret.second, "waiter emplace failed");
  }

  void remove(uint32_t seq) {
    Thread::LockGuard guard(mutex_);
    waiters_.erase(seq);
  }

  // receive is declared as noexcept to guarantee it will return normally, rather than via
  // an exception, if the program continues running. This allows for safe removal of the Waiter
  // from Waiters before the Waiter is destructed.
  void receive(Waiter&, uint32_t seq) noexcept;

private:
  using WaitersMap = absl::flat_hash_map<uint32_t, Waiter*>;

  Thread::MutexBasicLockable mutex_;
  WaitersMap waiters_ ABSL_GUARDED_BY(mutex_);
  bool is_receiver_active_ ABSL_GUARDED_BY(mutex_) = false;

  void wait() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mutex_) { cond_.wait(mutex_); }

  void notifyOne() ABSL_LOCKS_EXCLUDED(mutex_) { cond_.notifyOne(); }

  void notifyAll() ABSL_LOCKS_EXCLUDED(mutex_) { cond_.notifyAll(); }

  Thread::CondVar cond_;
};

using Singleton = Envoy::ThreadSafeSingleton<ProtocolClient>;

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
