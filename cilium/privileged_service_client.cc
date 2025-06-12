#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "cilium/privileged_service_client.h"

#include <asm-generic/socket.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "envoy/api/os_sys_calls_common.h"

#include "source/common/common/assert.h"
#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"

#include "starter/privileged_service_protocol.h"

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

ProtocolClient::ProtocolClient() : Protocol(CILIUM_PRIVILEGED_SERVICE_FD), seq_(0) {
  // Check that the Envoy process isn't running with privileges.
  // The only exception is CAP_NET_BIND_SERVICE (if explicitly excluded from being dropped).
  RELEASE_ASSERT((get_capabilities(CAP_EFFECTIVE) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0 &&
                     (get_capabilities(CAP_PERMITTED) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0,
                 "cilium-envoy running with privileges, exiting");

  if (!checkPrivilegedService()) {
    // No Cilium privileged service detected
    close();
  }

  // Validate that direct SO_MARK is now prohibited
  int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
  RELEASE_ASSERT(sockfd >= 0, "socket failed");

  uint32_t mark = 12345;
  int rc = ::setsockopt(sockfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
  RELEASE_ASSERT(rc == -1, "setsockopt");
  RELEASE_ASSERT(errno == EPERM, "setsockopt");

  ::close(sockfd);
}

ssize_t ProtocolClient::transact(MessageHeader& req, size_t req_len, const void* data,
                                 size_t data_len, int* fd, Response& resp, void* buf,
                                 size_t buf_size, bool assert) {
  // header will get cleared, store the expected message type
  auto expected_response_type = static_cast<MessageType>(resp.hdr_.msg_type_);

  RELEASE_ASSERT(buf_size <= RESPONSE_BUF_SIZE, "ProtocolClient::transact: invalid bufsize");

  // get next atomic sequence number
  req.msg_seq_ = ++seq_;
  // zero is reserved for "no response"
  if (req.msg_seq_ == 0) {
    req.msg_seq_ = ++seq_;
  }

  // Waiter must be inserted before we send the request, as another thread may receive it right
  // after and at that point a waiter must be found.
  // As the waiter is allocated in the stack, and is referenced via a pointer in the waiters_ map,
  // it MUST be removed from 'waiters_' before returning!
  Waiter waiter(&resp, buf, buf_size, fd);
  waiters_.insert(req.msg_seq_, &waiter);

  // send message without taking a lock
  ssize_t size = send_fd_msg(&req, req_len, data, data_len, *fd);
  if (!assert && size_t(size) != req_len + data_len) {
    // Only checkPrivilegedService() calls with assert=false, to support case where
    // cilium-envoy is run directly for testing purposes.
    // We get here if send fails due to privileged service not running.
    waiters_.remove(req.msg_seq_);
    return size;
  }

  // We use RELEASE_ASSERTs to make cilium-envoy crash and restart in cases when the privileged
  // service has become unresponsive, as that is the only way to recover from such failures.
  RELEASE_ASSERT(size != 0, "Cilium privileged service closed pipe");
  RELEASE_ASSERT(size_t(size) == req_len + data_len, "Cilium privileged service send failed");

  // buffer for value to receive
  char recv_buf[RESPONSE_BUF_SIZE];

  while (true) {
    // try become a receiver by taking the call_mutex_
    if (call_mutex_.tryLock()) {
      // Have to check if our response is already in to avoid entering the receive loop and never
      // seeing our response.
      size = waiters_.setReceiverActiveIfNoResponse(waiter, expected_response_type, req.msg_seq_);
      if (size < 0) {
        // Receive until we have a response or an error
        while (true) {
          size = recv_fd_msg(&resp, sizeof(resp), recv_buf, RESPONSE_BUF_SIZE, fd);
          RELEASE_ASSERT(size != 0, "Cilium privileged service closed pipe");
          if (size < 0) {
            // privileged service failed
            ENVOY_LOG(debug, "privileged service failed with {} (errno {})", size, errno);
            break;
          }
          // Must have enough data to decode the response header
          RELEASE_ASSERT(size_t(size) >= sizeof(resp),
                         "Cilium privileged service truncated response");

          // Is the response for us?
          if (resp.hdr_.msg_seq_ == req.msg_seq_) {
            RELEASE_ASSERT(resp.hdr_.msg_type_ == expected_response_type,
                           "Cilium privileged service unexpected response type");
            // Move data to our own 'buf'
            size = waiter.updateValue(size, recv_buf);
            break;
          }
          // The response is for one of the waiters, pass it on
          waiters_.wakeUp(resp.hdr_.msg_seq_, size, resp, recv_buf, fd);
        }
      }
      // Receive loop ended or not entered in the first place.
      // At this point 'size' is the valid return value, and the received data is in the buffers
      // given in the paramaters.
      call_mutex_.unlock();
      // Remove our waiter and pass receiver duties to one of the other waiters, if any.
      waiters_.signalReceiverOpen(req.msg_seq_);
      return size;
    }
    // tryLock failed, call_mutex_ not held.
    // There already is an active receiver, wait for a response from it
    // On succesful return the waiter is removed from `waiters_`.
    size = waiters_.wait(waiter, expected_response_type, req.msg_seq_);
    if (size != 0) {
      // Response received and waiter removed, return
      return size;
    }
    // Waiter woken up without a message.
    // It is still in `waiters_`, ready to receive updates from active receivers.
    // The active receiver may have returned, and we may need to become the next active receiver.
    // Loop back to try to become the receiver.
  }
}

bool ProtocolClient::checkPrivilegedService() {
  // Dump the effective capabilities of the privileged service process
  DumpRequest req;
  Response resp;
  uint8_t buf[RESPONSE_BUF_SIZE];
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &fd, resp, buf, sizeof(buf), false);
  if (size < ssize_t(sizeof(resp))) {
    return false;
  }
  std::string str(reinterpret_cast<char*>(buf), size - sizeof(resp));
  ENVOY_LOG_MISC(debug, "Cilium privileged service detected with following capabilities: {}", str);
  return true;
}

Envoy::Api::SysCallIntResult ProtocolClient::bpfOpen(const char* path) {
  if (!haveCiliumPrivilegedService()) {
    return {-1, EPERM};
  }

  BpfOpenRequest req;
  Response resp;
  size_t path_len = strlen(path);
  RELEASE_ASSERT(path_len <= PATH_MAX, "bpf open path too long");
  int fd = -1;
  ssize_t size = transact(req.hdr_, sizeof(req), path, path_len, &fd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  if (resp.return_value_ == INT_MAX) {
    resp.return_value_ = fd;
  }
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

Envoy::Api::SysCallIntResult ProtocolClient::bpfLookup(int fd, const void* key, uint32_t key_size,
                                                       void* value, uint32_t value_size) {
  if (!haveCiliumPrivilegedService()) {
    return {-1, EPERM};
  }

  BpfLookupRequest req(value_size);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), key, key_size, &fd, resp, value, value_size);
  RELEASE_ASSERT((size == ssize_t(sizeof(resp)) && resp.return_value_ == -1) ||
                     size == ssize_t(sizeof(resp) + value_size),
                 "invalid received bpf lookup value size");
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

Envoy::Api::SysCallIntResult ProtocolClient::setsockopt(int sockfd, int level, int optname,
                                                        const void* optval, socklen_t optlen) {
  if (!haveCiliumPrivilegedService()) {
    return {-1, EPERM};
  }

  SetSockOptRequest req(level, optname, optval, optlen);
  Response resp;
  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &sockfd, resp);
  RELEASE_ASSERT(size == ssize_t(sizeof(resp)), "invalid received response size");
  return Envoy::Api::SysCallIntResult{resp.return_value_, resp.errno_};
}

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
