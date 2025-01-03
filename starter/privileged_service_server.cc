#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "starter/privileged_service_server.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <algorithm>
#include <climits>
#include <cstdint>
#include <stdio.h>

#include "starter/privileged_service_protocol.h"

#include <linux/bpf.h>

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

ProtocolServer::~ProtocolServer() {
  // Wait for cilium-envoy to terminate
  if (pid_ != 0) {
    int rc;
    do {
      rc = ::waitpid(pid_, nullptr, 0);
    } while (rc == -1 && errno == EINTR);
  }
}

ProtocolServer::ProtocolServer(int pid, int pipe) : Protocol(pipe), pid_(pid) {}

void ProtocolServer::serve() {
  Buffer msg = {};

  while (true) {
    // wait for message
    int fd_in;
    // Leave one byte to the end of the buffer so that we can always zero-terminate string data.
    ssize_t size = recv_fd_msg(&msg, sizeof(msg) - 1, nullptr, 0, &fd_in);
    if (size < 0) {
      perror("recvmsg");
      if (errno == EPIPE || errno == EPERM) {
        break;
      }
      continue;
    }
    if (size == 0) {
      // pipe shut down, exiting
      break;
    }
    if (size_t(size) < sizeof(msg.hdr)) {
      fprintf(stderr, "received truncated request (%zd bytes), skipping\n", size);
      continue;
    }

    size_t msg_len = size_t(size);
    // Use the message buffer after request/response for the return value
    size_t header_size = std::max(msg_len, sizeof(Response));
    char* buf = msg.buf + header_size;
    size_t buf_size = sizeof(msg) - header_size;
    size_t value_len = 0; // set below to the actual length of the value to be returned
    int rc = 0;
    int fd_out = -1; // set below when 'rc' is a file descriptor

    switch (msg.hdr.msg_type_) {
    case TYPE_DUMP_REQUEST: // msg size == header size
      value_len = dump_capabilities(CAP_EFFECTIVE, buf, buf_size);
      break;
    case TYPE_BPF_OPEN_REQUEST: // msg size == header size + path length
      // zero terminate path name
      msg.bpf_open_req.path_[msg_len - sizeof(msg.bpf_open_req)] = '\0';
      {
        union bpf_attr attr = {};
        attr.pathname = uintptr_t(msg.bpf_open_req.path_);
        fd_out = rc = ::syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
      }
      break;
    case TYPE_BPF_LOOKUP_REQUEST: // key_size = msg_len - sizeof msg.bpf_lookup_req
      // require at least one byte key
      if (msg_len < sizeof(msg.bpf_lookup_req) + 1) {
        fprintf(stderr, "received truncated bpf lookup request (%zd bytes), skipping\n", msg_len);
        rc = -1;
        errno = EINVAL;
        break;
      }
      value_len = msg.bpf_lookup_req.value_size_;
      // Make sure the value fits into available space
      if (buf_size < value_len) {
        rc = -1;
        errno = EINVAL;
      } else {
        union bpf_attr attr = {};
        attr.map_fd = uint32_t(fd_in);
        attr.key = uintptr_t(msg.bpf_lookup_req.key_);
        attr.value = uintptr_t(buf);
        rc = ::syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
      }
      if (rc != 0) {
        value_len = 0;
      }
      break;
    case TYPE_SETSOCKOPT32_REQUEST: // msg_len == sizeof msg.setsockopt_req
      if (msg_len < sizeof(msg.setsockopt_req)) {
        fprintf(stderr, "received truncated setsockopt request (%zd bytes), skipping\n", msg_len);
        rc = -1;
        errno = EINVAL;
        break;
      }
      rc = ::syscall(__NR_setsockopt, fd_in, msg.setsockopt_req.level_, msg.setsockopt_req.optname_,
                     &msg.setsockopt_req.optval_, sizeof(msg.setsockopt_req.optval_));
      break;
    default:
      fprintf(stderr, "Unexpected privileged call type: %d\n", msg.hdr.msg_type_);
      rc = -1;
      errno = EINVAL;
    }

    // Close the received file descriptor
    if (fd_in != -1) {
      ::close(fd_in);
    }

    // Form the response in place
    msg.response.hdr_.msg_type_ = TYPE_RESPONSE;
    if (fd_out != -1) {
      // Pass a positive but invalid fd in return_value_, to be replaced with the passed
      // fd by the receiver.
      msg.response.return_value_ = INT_MAX;
      msg.response.errno_ = 0;
    } else {
      msg.response.return_value_ = rc;
      msg.response.errno_ = rc != -1 ? 0 : errno;
    }
    size = send_fd_msg(&msg, sizeof(msg.response), buf, value_len, fd_out);
    if (size < ssize_t(sizeof(msg.response) + value_len)) {
      perror("sendmsg");
    }

    // Close the sent file descriptor
    if (fd_out != -1) {
      ::close(fd_out);
    }
  }
}

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
