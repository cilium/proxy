#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "cilium/privileged_service_client.h"

#include <asm-generic/socket.h>
#include <linux/capability.h>
#include <linux/limits.h>
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
#include "source/common/common/logger.h"

#include "starter/privileged_service_protocol.h"

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

ProtocolClient::ProtocolClient() : Protocol(CILIUM_PRIVILEGED_SERVICE_FD), seq_(0) {
  // Check that the Envoy process isn't running with privileges.
  // The only exception is CAP_NET_BIND_SERVICE (if explicitly excluded from being dropped).
  RELEASE_ASSERT((getCapabilities(CAP_EFFECTIVE) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0 &&
                     (getCapabilities(CAP_PERMITTED) & ~(1UL << CAP_NET_BIND_SERVICE)) == 0,
                 "cilium-envoy running with privileges, exiting");

  if (!checkPrivilegedService()) {
    ENVOY_LOG(warn, "Cilium privileged service not present");
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
                                 size_t buf_size) {
  RELEASE_ASSERT(buf_size <= RESPONSE_BUF_SIZE, "ProtocolClient::transact: invalid bufsize");
  uint32_t seq;

  // get next atomic sequence number
  do {
    seq = ++seq_;
  } while (seq == 0); // zero is reserved for "no response"
  req.msg_seq_ = seq;

  // Set up a waiter in the stack before we send anything so that the waiter exists as soon as it is
  // possible for a concurrent receiver to receive the response.
  Waiter waiter;
  waiters_.insert(seq, &waiter);

  // send message after a waiter has been established.
  ssize_t size = sendFdMsg(&req, req_len, data, data_len, *fd);
  if (size > 0) {
    if (size_t(size) == req_len + data_len) {
      // Request was sent completely, receive the response
      size = waiterReceive(waiter, seq);
    } else {
      // send was truncated, return 0 to indicate failure
      size = 0;
    }
  }

  // waiter must be removed on all return paths. This is the only one.
  waiters_.remove(seq);
  return size > 0 ? waiter.getResponse(resp, buf, buf_size, fd) : size;
}

ssize_t ProtocolClient::waiterReceive(Waiter& waiter, uint32_t seq) noexcept {
  while (true) {
    // Try become a receiver by taking the call_mutex_.
    if (call_mutex_.tryLock()) {
      // Check if our response is already in, otherwise we could enter the receive loop and never
      // receive our response.
      ssize_t size = waiters_.setReceiverActiveIfNoResponse(waiter, seq);
      if (size == 0) {
        // Receive until we have a response or an error
        while (true) {
          size = waiter.recvFdMsg(*this);
          RELEASE_ASSERT(size != 0, "Cilium privileged service closed pipe");
          if (size < 0) {
            // privileged service failed
            ENVOY_LOG(debug, "privileged service failed with {} (errno {})", size, errno);
            break;
          }
          // Must have enough data to decode the response header
          RELEASE_ASSERT(size_t(size) >= sizeof(Response),
                         "Cilium privileged service truncated response");
          RELEASE_ASSERT(waiter.msgType() == MessageType::TypeResponse,
                         "Cilium privileged service unexpected response type");

          // Is the response for us?
          if (waiter.seq() == seq) {
            break;
          }
          // The response is for one of the waiters, pass it on
          waiters_.wakeUp(waiter);
        }
      }

      // Receive loop ended or not entered in the first place.
      call_mutex_.unlock();
      // Pass receiver duties to one of the other waiters, if any.
      waiters_.signalReceiverOpen();
      return size;
    }

    // tryLock failed, call_mutex_ not held.
    // There already is an active receiver, wait for a response from it.
    ssize_t size = waiters_.wait(waiter, seq);
    if (size != 0) {
      return size;
    }
    // Waiter woken up without a response.
    // Loop back to try to become the receiver.
  }
}

bool ProtocolClient::checkPrivilegedService() {
  // Dump the effective capabilities of the privileged service process
  DumpRequest req;
  Response resp;
  uint8_t buf[RESPONSE_BUF_SIZE];
  int fd = -1;

  ssize_t size = transact(req.hdr_, sizeof(req), nullptr, 0, &fd, resp, buf, sizeof(buf));
  if (size < ssize_t(sizeof(resp))) {
    ENVOY_LOG_MISC(warn, "Cilium privileged service detection failed with return code: {}", size);
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
