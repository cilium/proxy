#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include "starter/privileged_service_protocol.h"

#include <errno.h>
#include <sys/syscall.h>
#include <sys/unistd.h>
#include <asm-generic/socket.h>
#include <bits/types/struct_iovec.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/capability.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

// Capabiilty names used in DumpCapabilities responses.
static const char* cap_names[64] = {
    "CAP_CHOWN",              //  0
    "CAP_DAC_OVERRIDE",       //  1
    "CAP_DAC_READ_SEARCH",    //  2
    "CAP_FOWNER",             //  3
    "CAP_FSETID",             //  4
    "CAP_KILL",               //  5
    "CAP_SETGID",             //  6
    "CAP_SETUID",             //  7
    "CAP_SETPCAP",            //  8
    "CAP_LINUX_IMMUTABLE",    //  9
    "CAP_NET_BIND_SERVICE",   // 10
    "CAP_NET_BROADCAST",      // 11
    "CAP_NET_ADMIN",          // 12
    "CAP_NET_RAW",            // 13
    "CAP_IPC_LOCK",           // 14
    "CAP_IPC_OWNER",          // 15
    "CAP_SYS_MODULE",         // 16
    "CAP_SYS_RAWIO",          // 17
    "CAP_SYS_CHROOT",         // 18
    "CAP_SYS_PTRACE",         // 19
    "CAP_SYS_PACCT",          // 20
    "CAP_SYS_ADMIN",          // 21
    "CAP_SYS_BOOT",           // 22
    "CAP_SYS_NICE",           // 23
    "CAP_SYS_RESOURCE",       // 24
    "CAP_SYS_TIME",           // 25
    "CAP_SYS_TTY_CONFIG",     // 26
    "CAP_MKNOD",              // 27
    "CAP_LEASE",              // 28
    "CAP_AUDIT_WRITE",        // 29
    "CAP_AUDIT_CONTROL",      // 30
    "CAP_SETFCAP",            // 31
    "CAP_MAC_OVERRIDE",       // 32
    "CAP_MAC_ADMIN",          // 33
    "CAP_SYSLOG",             // 34
    "CAP_WAKE_ALARM",         // 35
    "CAP_BLOCK_SUSPEND",      // 36
    "CAP_AUDIT_READ",         // 37
    "CAP_PERFMON",            // 38
    "CAP_BPF",                // 39
    "CAP_CHECKPOINT_RESTORE", // 40
    "CAP_41",
    "CAP_42",
    "CAP_43",
    "CAP_44",
    "CAP_45",
    "CAP_46",
    "CAP_47",
    "CAP_48",
    "CAP_49",
    "CAP_50",
    "CAP_51",
    "CAP_52",
    "CAP_53",
    "CAP_54",
    "CAP_55",
    "CAP_56",
    "CAP_57",
    "CAP_58",
    "CAP_59",
    "CAP_60",
    "CAP_61",
    "CAP_62",
    "CAP_63",
};

// Get a 64-bit set of capabilities of the given kind
uint64_t get_capabilities(cap_flag_t kind) {
  struct __user_cap_header_struct hdr{_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct data[2];
  memset(&data, 0, sizeof(data));
  int rc = ::syscall(SYS_capget, &hdr, &data, sizeof(data));
  if (rc != 0) {
    perror("capget");
    exit(1);
  }

  if (kind == CAP_INHERITABLE) {
    return data[0].inheritable | uint64_t(data[1].inheritable) << 32;
  }
  if (kind == CAP_PERMITTED) {
    return data[0].permitted | uint64_t(data[1].permitted) << 32;
  }
  if (kind == CAP_EFFECTIVE) {
    return data[0].effective | uint64_t(data[1].effective) << 32;
  }
  fprintf(stderr, "get_capabilities: invalid kind: %d\n", kind);
  ::abort();
  return 0;
}

// dumpCaps returns the capabilities of the given kind in string form.
size_t dump_capabilities(cap_flag_t kind, char* buf, size_t buf_size) {
  size_t remaining = buf_size;
  uint64_t caps = get_capabilities(kind);

  auto append = [&](const char* str) {
    auto len = strlen(str);
    if (len < remaining) {
      memcpy(buf, str, len);
      remaining -= len;
      buf += len;
    }
  };

  for (int i = 0, n = 0; i < 64; i++) {
    if (caps & (1UL << i)) {
      if (n > 0)
        append(", ");
      append(cap_names[i]);
      n++;
    }
  }

  return buf_size - remaining;
}

Protocol::~Protocol() { close(); }

Protocol::Protocol(int fd) : fd_(fd) {}

void Protocol::close() {
  if (fd_ != -1) {
    ::close(fd_);
  }
  fd_ = -1;
}

namespace {

static inline struct msghdr init_iov(struct iovec iov[2], const void* header, ssize_t headerlen,
                                     const void* data, ssize_t datalen) {
  struct msghdr msg{};
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  iov[0].iov_base = const_cast<void*>(header);
  iov[0].iov_len = headerlen;
  if (data && datalen > 0) {
    msg.msg_iovlen = 2;
    iov[1].iov_base = const_cast<void*>(data);
    iov[1].iov_len = datalen;
  }
  return msg;
}

} // namespace

ssize_t Protocol::send_fd_msg(const void* header, ssize_t headerlen, const void* data,
                              ssize_t datalen, int fd) {
  struct iovec iov[2];
  struct msghdr msg = init_iov(iov, header, headerlen, data, datalen);
  union {
    struct cmsghdr cmsghdr;
    char control[CMSG_SPACE(sizeof(int))];
  } cmsgu;
  struct cmsghdr* cmsg;

  // set up msg control for an fd?
  if (fd != -1) {
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *reinterpret_cast<int*>(CMSG_DATA(cmsg)) = fd;
  }

  // send the request
  ssize_t size;
  do {
    size = sendmsg(fd_, &msg, 0);
  } while (size < 0 && errno == EINTR);

  if (size >= 0 && size != headerlen + datalen) {
    fprintf(stderr, "sendmsg truncated (%zd < %zd)\n", size, headerlen + datalen);
  }
  return size;
}

ssize_t Protocol::recv_fd_msg(const void* header, ssize_t headersize, const void* data,
                              ssize_t datasize, int* fd) {
  struct iovec iov[2];
  struct msghdr msg = init_iov(iov, header, headersize, data, datasize);
  union {
    struct cmsghdr cmsghdr;
    char control[CMSG_SPACE(sizeof(int))];
  } cmsgu;
  msg.msg_control = cmsgu.control;
  msg.msg_controllen = sizeof(cmsgu.control);

  ssize_t size;
  do {
    size = recvmsg(fd_, &msg, 0);
  } while (size < 0 && errno == EINTR);

  if (size >= 0 && fd) {
    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
      *fd = *reinterpret_cast<int*>(CMSG_DATA(cmsg));
    } else {
      *fd = -1;
    }
  }
  return size;
}

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
