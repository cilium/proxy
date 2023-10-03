#pragma once

#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

// Use Envoy version of this if defined, otherwise roll a simple stderr one without further
// dependencies
#ifndef RELEASE_ASSERT
#define _ASSERT_IMPL(CONDITION, CONDITION_STR, DETAILS)                                            \
  do {                                                                                             \
    if (!(CONDITION)) {                                                                            \
      fprintf(stderr, "assert failure: %s. Details: %s", CONDITION_STR, (DETAILS));                \
      ::abort();                                                                                   \
    }                                                                                              \
  } while (false)
#define RELEASE_ASSERT(X, DETAILS) _ASSERT_IMPL(X, #X, DETAILS)
#endif

// Kernel headers may miss CAP_BPF added in Linux 5.8
#ifndef CAP_BPF
#define CAP_BPF 39
#endif

#ifndef _SYS_CAPABILITY_H
// These are normally defined in <sys/capability.h> added in libcap-dev package. Define these here
// to avoid that dependency due to complications in cross-compilation for Intel/Arm.
typedef enum {
  CAP_EFFECTIVE = 0,  /* Specifies the effective flag */
  CAP_PERMITTED = 1,  /* Specifies the permitted flag */
  CAP_INHERITABLE = 2 /* Specifies the inheritable flag */
} cap_flag_t;
#endif

namespace Envoy {
namespace Cilium {
namespace PrivilegedService {

uint64_t get_capabilities(cap_flag_t kind);
size_t dump_capabilities(cap_flag_t kind, char* buf, size_t buf_size);

#define CILIUM_PRIVILEGED_SERVICE_FD 3

// Communication with the privileged service is performed with a simple message protocol over a Unix
// domain socket pair using the SOCK_SEQPACKET type, preserving record boundaries without explicitly
// encoding a length field.
// Each message starts with a 4-byte type and a 4-byte sequence number, both in the host byte order,
// which are followed by message type specific variable length data.

// Supported message types
typedef enum {
  TYPE_RESPONSE = 1,
  TYPE_DUMP_REQUEST = 2,
  TYPE_BPF_OPEN_REQUEST = 3,
  TYPE_BPF_LOOKUP_REQUEST = 4,
  TYPE_SETSOCKOPT32_REQUEST = 5,
} MessageType;

// Common message header
// Note that C++ inheritance can not be used as all the data members need to be on the same struct
// definition. This means that we must contain the MessageHeader as the first member of each message
// definition.
struct MessageHeader {
  uint32_t msg_type_ = 0;
  uint32_t msg_seq_ = 0; // reflected in response

  MessageHeader() {}
  MessageHeader(MessageType t) : msg_type_(t) {}
};

// Response passes the return value and errno code from the system call, followed by optional
// data depending on the request type. Note that file descriptor return value is passed using the
// message control channel (ref. man 2 recvmsg).
struct Response {
  Response() : hdr_(TYPE_RESPONSE) {}

  struct MessageHeader hdr_;
  int return_value_;
  int errno_;
  uint8_t data_[];
};

// Dump requests consists only of the message header, but with the TYPE_DUMP_REQUEST.
// Response contains the effective capabilitites in a string form.
struct DumpRequest {
  DumpRequest() : hdr_(TYPE_DUMP_REQUEST) {}

  struct MessageHeader hdr_;
};

// BpfOpenRequest has a variable length path after the message header.
// Path need not be 0-terminated.
// Response must be a SyscallResponse. The file descriptor is returned in the message control
// channel (see man 2 recvmsg).
struct BpfOpenRequest {
  BpfOpenRequest() : hdr_(TYPE_BPF_OPEN_REQUEST) {}

  struct MessageHeader hdr_;
  char path_[];
};

// BpfLookupRequest passes the expected value size and a variable length key.
// Key size is not explicitly passed, as it is deduced from the message length.
// In a successful case the response contains the value returned by the bpf map lookup.
struct BpfLookupRequest {
  BpfLookupRequest(uint32_t value_size) : hdr_(TYPE_BPF_LOOKUP_REQUEST), value_size_(value_size) {}

  struct MessageHeader hdr_;
  uint32_t value_size_;
  uint8_t key_[];
};

// SetSockOptRequest only supports setting 4-byte options.
// Response is SyscallResponse.
struct SetSockOptRequest {
  SetSockOptRequest(int level, int optname, const void* optval, socklen_t optlen)
      : hdr_(TYPE_SETSOCKOPT32_REQUEST), level_(level), optname_(optname) {
    RELEASE_ASSERT(optlen == sizeof(uint32_t), "optlen must be 4 bytes");
    memcpy(&optval_, optval, optlen);
  }

  struct MessageHeader hdr_;
  int level_;
  int optname_;
  uint32_t optval_;
};

// Protocol implements the logic for communicating with the privileged service.
class Protocol {
public:
  Protocol(int fd);
  ~Protocol();

  void close();
  bool is_open() const { return fd_ != -1; }

  ssize_t send_fd_msg(const void* header, ssize_t headerlen, const void* data = nullptr,
                      ssize_t datalen = 0, int fd = -1);
  ssize_t recv_fd_msg(const void* header, ssize_t headersize, const void* data = nullptr,
                      ssize_t datasize = 0, int* fd = nullptr);

protected:
  int fd_;
};

} // namespace PrivilegedService
} // namespace Cilium
} // namespace Envoy
