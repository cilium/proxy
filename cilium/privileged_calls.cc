#include "cilium/privileged_calls.h"

#include <dirent.h>

#include <linux/bpf.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "source/common/common/assert.h"

// Drop all capabilities before Envoy is initialized. If the process is started with any granted
// capabilities, fork a child process that keeps all those capabilities at file unit init time
// (before main() is run). Before the fork, assert that no child processes or threads have yet been
// created. After the fork drop all capabilities and prevent any capabilitites from being re-aquired
// later. This way all the Envoy code runs without any capabilities.
//
// The forked thread implements a simple protocol over a pair of Unix domain sockets that allows
// Envoy to ask for a limited set of privileged operations to be performed. These are:
// - setting socket options SO_MARK and IP(V6)_TRANSPARENT
// - Bpf map open and lookup (read only)

#ifndef _SYS_CAPABILITY_H
// These are normally defined in <sys/capability.h> added in libcap-dev package.  Define these here
// to avoid that dependency due to complications in cross-compilation for Intel/Arm.
typedef enum {
    CAP_EFFECTIVE = 0,                 /* Specifies the effective flag */
    CAP_PERMITTED = 1,                 /* Specifies the permitted flag */
    CAP_INHERITABLE = 2                /* Specifies the inheritable flag */
} cap_flag_t;
#endif

// Communication with the privileged process is performed with a simple message protocol over a Unix
// domain socket pair using the SOCK_SEQPACKET type, preserving record boundaries without explicitly
// encoding a length field.
// Each message starts with a 4-byte type and a 4-byte sequence number, both in the host byte order,
// which are followed by message type specific variable length data.

// Supported message types
typedef enum {
  TYPE_SYSCALL_RESPONSE = 1,
  TYPE_VALUE_RESPONSE = 2,
  TYPE_DUMP_REQUEST = 3,
  TYPE_BPF_OPEN_REQUEST = 4,
  TYPE_BPF_LOOKUP_REQUEST = 5,
  TYPE_SETSOCKOPT32_REQUEST = 6,
} MessageType;

// Common message header
struct MessageHeader {
  uint32_t msg_type_ = 0;
  uint32_t msg_seq_ = 0; // reflected in response

  MessageHeader() {}
  MessageHeader(MessageType t) : msg_type_(t) {}
};

// Dump requests consists only of the message header, but with the TYPE_DUMP_REQUEST.
// Must be responded to with a ValueResponse containing the effective capabilitites in
// a string form.
struct DumpRequest {
  struct MessageHeader hdr_;

  DumpRequest() : hdr_(TYPE_DUMP_REQUEST) {}
};

// BpfOpenRequest has a variable length path after the message header.
// Path need not be 0-terminated.
// Response must be a SyscallResponse. The file descriptor is returned in the message control
// channel (see man 2 recvmsg).
struct BpfOpenRequest {
  struct MessageHeader hdr_;
  char path_[];

  BpfOpenRequest() : hdr_(TYPE_BPF_OPEN_REQUEST) {}
};

// BpfLookupRequest passes the expected value size and a variable length key.
// Key size is not explicitly passed, as it is deduced from the message length.
// In a successful case the response is of type ValueResponse containing the found map value.
// In the fail case the response is SyscallResponse containing the return code and errno value.
struct BpfLookupRequest {
  struct MessageHeader hdr_;
  uint32_t value_size_;
  uint8_t key_[];

  BpfLookupRequest(uint32_t value_size) : hdr_(TYPE_BPF_LOOKUP_REQUEST), value_size_(value_size) {}
};

// SetSockOptRequest only supports setting 4-byte options.
// Response is SyscallResponse.
struct SetSockOptRequest {
  struct MessageHeader hdr_;
  int level_;
  int optname_;
  uint32_t optval_;

  SetSockOptRequest(int level, int optname, const void *optval, socklen_t optlen)
    : hdr_(TYPE_SETSOCKOPT32_REQUEST), level_(level), optname_(optname) {
    RELEASE_ASSERT(optlen == sizeof(uint32_t), "optlen must be 4 bytes");
    memcpy(&optval_, optval, optlen);
  }
};

// SyscallResponse passes the return value and errno code from the system call. Note that file
// descriptor return value is passed using the message control channel (ref. man 2 recvmsg).
struct SyscallResponse {
  struct MessageHeader hdr_;
  Envoy::Api::SysCallIntResult ret_;

  SyscallResponse() : hdr_(TYPE_SYSCALL_RESPONSE) {}
};

// ValueResponse carries variable length data after the message header. Length of the data is
// computed from the message length.
struct ValueResponse {
  struct MessageHeader hdr_;
  uint8_t data_[];

  ValueResponse() : hdr_(TYPE_VALUE_RESPONSE) {}
};

// Capabiilty names used in DumpCapabilites responses.
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
static uint64_t getCaps(unsigned int kind) {
  ASSERT(kind <= CAP_INHERITABLE, "invalid capability kind");

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
  return data[0].effective | uint64_t(data[1].effective) << 32;
}

// dumpCaps returns the capabilities of the given kind in string form.
static std::string dumpCaps(cap_flag_t kind) {
  uint64_t caps = getCaps(kind);

  std::string output;
  bool first = true;
  for (int i=0; i < 64; i++) {
    if (caps & (1 << i)) {
      if (!first) {
	output.append(", ");
      }
      first = false;
      output.append(cap_names[i]);
    }
  }
  return output;
}

// DropCaps implements the logic for forking a privileged thread and dropping all capabilities from
// the process (the main thread) all other (future) child processes and threads.
class DropCaps {
public:
  ~DropCaps() {
    if (fd_ != -1) {
      // Tell privileged process to exit
      close(fd_);
      // Wait for the privileged process to terminate
      if (pid_ != 0) {
	int rc;
	do {
	  rc = ::waitpid(pid_, nullptr, 0);
	} while (rc == -1 && errno == EINTR);
      }
    }
  }

  DropCaps() : caps_(getCaps(CAP_EFFECTIVE)) {
    // Make sure no child processes exist yet
    // waitpid(-1) raises ECHILD when children do not exist,
    // WNOHANG prevents the calling thread to not hang when there are child processes.
    RELEASE_ASSERT(::waitpid(-1, nullptr, WNOHANG) < 0 && errno == ECHILD,
		   "Capabilities must be dropped before any child processes are forked");

    // Assert that the task has no other threads than the main thread,
    // for which the thread id is the process id
    int pid = ::getpid();
    DIR *proc_dir = opendir("/proc/self/task");
    RELEASE_ASSERT(proc_dir != nullptr, "/proc/self/task does not exists");
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
      if(entry->d_name[0] == '.')
	continue;
      // dir entry name is the thread id
      int id = atoi(entry->d_name);
      RELEASE_ASSERT(id == pid, "Capabilities must be dropped before any threads are created");
    }
    closedir(proc_dir);

    // Start a privileged thread if we have any capabilities to start with
    if (caps_ != 0) {
      int fds[2];
      int rc = socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, fds);
      RELEASE_ASSERT(rc == 0, "socketpair failed");

      pid_ = fork();
      RELEASE_ASSERT(pid_ != -1, "fork failed");

      if (pid_ == 0) {
	// in privileged process, close the parent end of the pipe
	close(fds[0]);
	privileged_process(fds[1]);
	exit(0);
      }

      // in parent, close the child end of the pipe
      close(fds[1]);
      fd_ = fds[0];

      // Make sure the child process started
      RELEASE_ASSERT(::waitpid(pid_, nullptr, WNOHANG) == 0, "Child process did not start!");

      // Get the effective capabilities from the privileged process
      std::string str = dumpCapabilities();
      fprintf(stderr, "Privileged process started with capabilities: %s\n", str.c_str());
    }

    // Unconditionally drop all capabilities
    struct __user_cap_header_struct hdr{_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2];
    memset(&data, 0, sizeof(data));
    if (::syscall(SYS_capset, &hdr, &data, sizeof(data)) != 0) {
      perror("capset");
      exit(1);
    }

    // Drop bounding set to prevent regaining dropped capabilities
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
      perror("prctl(PR_SET_NO_NEW_PRIVS)");
      exit(1);
    }

    RELEASE_ASSERT(getCaps(CAP_EFFECTIVE) == 0 && getCaps(CAP_PERMITTED) == 0,
		   "Failed dropping privileges");
    fprintf(stderr, "Envoy process capabilities successfully dropped\n");

#ifndef CAP_BPF
#define CAP_BPF			39
#endif
    // Validate BPF if have CAP_BPF or CAP_SYS_ADMIN
    if (caps_ & (1UL << CAP_BPF | 1UL << CAP_SYS_ADMIN)) {
      // Try open a bpf map (expect fail)
      auto res = bpfOpen("/var/run/cilium/example_bpf_map");
      RELEASE_ASSERT(res.return_value_ == -1, "bpfOpen");
      RELEASE_ASSERT(res.errno_ == ENOENT, "bpfOpen");

      // Try bpf lookup on stderr (expect fail)
      int key, value;
      res = bpfLookup(0, &key, sizeof(key), &value, sizeof(value));
      RELEASE_ASSERT(res.return_value_ == -1, "bpfLookup(small)");
      RELEASE_ASSERT(res.errno_ == EINVAL, "bpfLookup(small)");

      int large_value[10];
      res = bpfLookup(-1, &key, sizeof(key), &large_value, sizeof(large_value));
      RELEASE_ASSERT(res.return_value_ == -1, "bpfLookup(large)");
      RELEASE_ASSERT(res.errno_ == EBADF, "bpfLookup(large)");
    }

    // Validate SO_MARK if have CAP_NET_ADMIN
    if (caps_ & 1UL << CAP_NET_ADMIN) {
      int sockfd = socket(AF_INET, SOCK_STREAM, 0);
      RELEASE_ASSERT(sockfd >= 0, "socket failed");

      uint32_t mark = 12345;
      auto res = setSockOpt(sockfd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
      RELEASE_ASSERT(res.return_value_ == 0, "setsockopt");

      uint32_t value;
      socklen_t optlen = sizeof(value);
      int rc = ::getsockopt(sockfd, SOL_SOCKET, SO_MARK, &value, &optlen);
      RELEASE_ASSERT(rc == 0, "getsockopt");

      RELEASE_ASSERT(value == mark, "invalid SO_MARK value");
      close(sockfd);
    }
  }

  static void privileged_process(int pipe);
  static ssize_t send_fd_msg(int pipe, const void *header, ssize_t headerlen,
			       const void *data = nullptr, ssize_t datalen = 0, int fd = -1);
  static ssize_t recv_fd_msg(int pipe, const void *header, ssize_t headersize,
			       const void *data = nullptr, ssize_t datasize = 0, int *fd = nullptr);

  ssize_t transact(MessageHeader& req, size_t req_len, const void *data, size_t datalen, int *fd, MessageHeader& resp, size_t resp_size, void *buf = nullptr, size_t bufsize = 0) {
    // Serialize privileged calls
    int rc = pthread_mutex_lock(&call_mutex_);
    RELEASE_ASSERT(rc == 0, "pthread_mutex_lock");

    req.msg_seq_ = ++seq_;
    ssize_t size = send_fd_msg(fd_, &req, req_len, data, datalen, *fd);
    RELEASE_ASSERT(size != 0, "privileged process closed pipe");
    RELEASE_ASSERT(size > 0, "privileged process send failed");

    uint32_t expected_response_type = resp.msg_type_;
    size = recv_fd_msg(fd_, &resp, resp_size, buf, bufsize, fd);
    RELEASE_ASSERT(size != 0, "privileged process closed pipe");
    RELEASE_ASSERT(size < 0 || size_t(size) >= resp_size, "privileged process truncated response");
    RELEASE_ASSERT(resp.msg_seq_ == req.msg_seq_, "privileged process response out of sequence");
    RELEASE_ASSERT(expected_response_type == 0 || resp.msg_type_ == expected_response_type,
		   "privileged process unexpected response type");

    rc = pthread_mutex_unlock(&call_mutex_);
    RELEASE_ASSERT(rc == 0, "pthread_mutex_unlock");
    return size;
  }

private:
  uint64_t caps_; // Effective capabilities at start
  pthread_mutex_t call_mutex_ = PTHREAD_MUTEX_INITIALIZER;
  static uint32_t seq_; // access protected by call_mutex_

  int pid_ = 0; // child pid
  int fd_ = -1; // our end of the datagram pipe
};
uint32_t DropCaps::seq_ = 0;

void DropCaps::privileged_process(int pipe) {
  // Bpf needs relaxed limits on memory
  struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
  int ret = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (ret != 0) {
    perror("setrlimit(RLIMIT_MEMLOCK)");
  }

  while (true) {
    // receive buffer
    union {
      MessageHeader hdr;
      DumpRequest dump_req;
      BpfOpenRequest bpf_open_req;
      BpfLookupRequest bpf_lookup_req;
      SetSockOptRequest setsockopt_req;
      
      // resposes use the same buffer, so they inherit the message sequence number from the request
      SyscallResponse syscall_response;
      ValueResponse value_response;

      // make space for the largest possible request
      char buf[sizeof(BpfOpenRequest) + PATH_MAX + 1];
    } msg = {};

    // wait for message
    int fd;
    ssize_t size = recv_fd_msg(pipe, &msg, sizeof(msg) - 1, nullptr, 0, &fd);
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
    int rc;
    switch (msg.hdr.msg_type_) {
    case TYPE_DUMP_REQUEST: {
      std::string caps = dumpCaps(CAP_EFFECTIVE);
      msg.hdr.msg_type_ = TYPE_VALUE_RESPONSE;
      send_fd_msg(pipe, &msg, sizeof(msg.value_response), caps.data(), caps.length());
    }
      break;
    case TYPE_BPF_OPEN_REQUEST: {
      // zero terminate path name
      msg.bpf_open_req.path_[msg_len - sizeof(msg.bpf_open_req)] = '\0';
      union bpf_attr attr = {};
      attr.pathname = uintptr_t(msg.bpf_open_req.path_);
      fd = ::syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
      msg.hdr.msg_type_ = TYPE_SYSCALL_RESPONSE;
      msg.syscall_response.ret_ = {fd, fd != -1 ? 0 : errno};
      size = send_fd_msg(pipe, &msg, sizeof(msg.syscall_response), nullptr, 0, fd);
      if (size != ssize_t(sizeof(msg.syscall_response))) {
	perror("bpf open sendmsg");
      }
    }
      break;
    case TYPE_BPF_LOOKUP_REQUEST: {
      // Use the remainder of the message buffer for the return value
      char *buf = msg.buf + msg_len;
      // Make sure the value fits into available space
      if (msg.bpf_lookup_req.value_size_ > sizeof(msg) - msg_len) {
	rc = -1;
	errno = EINVAL;
      } else {
	union bpf_attr attr = {};
	attr.map_fd = uint32_t(fd);
	attr.key = uintptr_t(msg.bpf_lookup_req.key_);
	attr.value = uintptr_t(buf);
	rc = ::syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
      }
      if (rc != 0) {
	msg.hdr.msg_type_ = TYPE_SYSCALL_RESPONSE;
	msg.syscall_response.ret_ = {rc, errno};
	size = send_fd_msg(pipe, &msg, sizeof(msg.syscall_response));
	if (size != ssize_t(sizeof(msg.syscall_response))) {
	  perror("bpf lookup fail sendmsg");
	}
      } else {
	msg.hdr.msg_type_ = TYPE_VALUE_RESPONSE;
	size = send_fd_msg(pipe, &msg, sizeof(msg.value_response), buf, msg.bpf_lookup_req.value_size_);
	if (size < ssize_t(sizeof(msg.value_response)) + msg.bpf_lookup_req.value_size_) {
	  perror("bpf lookup sendmsg");
	}
      }
    }
      break;
    case TYPE_SETSOCKOPT32_REQUEST:
      rc = ::syscall(__NR_setsockopt, fd, msg.setsockopt_req.level_, msg.setsockopt_req.optname_, &msg.setsockopt_req.optval_, sizeof(msg.setsockopt_req.optval_));
      msg.hdr.msg_type_ = TYPE_SYSCALL_RESPONSE;
      msg.syscall_response.ret_ = {rc, rc != -1 ? 0 : errno};
      size = send_fd_msg(pipe, &msg, sizeof(msg.syscall_response));
      if (size < ssize_t(sizeof(msg.syscall_response))) {
	perror("setsockopt sendmsg");
      }
      break;
    default:
      fprintf(stderr, "Unknown privileged call type: %d\n", msg.hdr.msg_type_);
    }
    // Close the received file descriptor
    if (fd != -1) {
      close(fd);
    }
  }
}

static inline struct msghdr
init_iov(struct iovec iov[2], const void *header, ssize_t headerlen, const void *data, ssize_t datalen) {
  struct msghdr msg{};
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  iov[0].iov_base = const_cast<void *>(header);
  iov[0].iov_len = headerlen;
  if (data && datalen > 0) {
    msg.msg_iovlen = 2;
    iov[1].iov_base = const_cast<void *>(data);
    iov[1].iov_len = datalen;
  }
  return msg;
}

ssize_t DropCaps::send_fd_msg(int pipe, const void *header, ssize_t headerlen, const void *data, ssize_t datalen, int fd) {
  struct iovec  iov[2];
  struct msghdr msg = init_iov(iov, header, headerlen, data, datalen);
  union {
    struct cmsghdr  cmsghdr;
    char            control[CMSG_SPACE(sizeof (int))];
  } cmsgu;
  struct cmsghdr *cmsg;

  // set up msg control, optionally with an fd
  if (fd != -1) {
    msg.msg_control = cmsgu.control;
    msg.msg_controllen = sizeof(cmsgu.control);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_len = CMSG_LEN(sizeof (int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    *reinterpret_cast<int *>(CMSG_DATA(cmsg)) = fd;
  }
  
  // send the request
  ssize_t size;
  do {
    size = sendmsg(pipe, &msg, 0);
  } while (size < 0 && errno == EINTR);

  if (size >= 0 && size != headerlen+datalen) {
    fprintf(stderr, "sendmsg truncated (%zd < %zd)\n", size, headerlen+datalen);
  }
  return size;
}

ssize_t DropCaps::recv_fd_msg(int pipe, const void *header, ssize_t headersize, const void *data, ssize_t datasize, int *fd) {
  struct iovec  iov[2];
  struct msghdr msg = init_iov(iov, header, headersize, data, datasize);
  union {
    struct cmsghdr cmsghdr;
    char           control[CMSG_SPACE(sizeof (int))];
  } cmsgu;
  msg.msg_control = cmsgu.control;
  msg.msg_controllen = sizeof(cmsgu.control);

  ssize_t size;
  do {
    size = recvmsg(pipe, &msg, 0);
  } while (size < 0 && errno == EINTR);

  if (size >= 0 && fd) {
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
	cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      *fd = *reinterpret_cast<int *>(CMSG_DATA(cmsg));
    } else {
      *fd = -1;
    }
  }
  return size;
}

static DropCaps caps;

std::string dumpCapabilities() {
  auto req = DumpRequest();
  auto resp = ValueResponse();
  uint8_t buf[1024];
  int fd = -1;
  auto size = caps.transact(req.hdr_, sizeof(req), nullptr, 0, &fd, resp.hdr_, sizeof(resp), buf, sizeof(buf));
  return std::string(reinterpret_cast<char *>(buf), size - sizeof(resp));
}

Envoy::Api::SysCallIntResult bpfOpen(const char *path) {
  auto req = BpfOpenRequest();
  size_t path_len = strlen(path);
  RELEASE_ASSERT(path_len <= PATH_MAX, "bpf open path too long");
  auto resp = SyscallResponse();
  int fd = -1;
  caps.transact(req.hdr_, sizeof(req), path, path_len, &fd, resp.hdr_, sizeof(resp));
  resp.ret_.return_value_ = fd;
  return resp.ret_;
}

Envoy::Api::SysCallIntResult bpfLookup(int fd, const void *key, uint32_t key_size, void* value, uint32_t value_size) {
  auto req = BpfLookupRequest(value_size);
  MessageHeader resp; // untyped response
  Envoy::Api::SysCallIntResult ret;  // the only documented value for bpf lookup
  // Use ret as buffer for values smaller than SysCallResult
  void *buf = &ret;
  uint32_t buf_size = sizeof(ret);
  // Write directly to the value, if it is big enough to hold the syscall response when needed
  if (value_size >= buf_size) {
    buf = value;
    buf_size = value_size;
  }
  ssize_t size = caps.transact(req.hdr_, sizeof(req), key, key_size, &fd, resp, sizeof(resp), buf, buf_size);
  if (resp.msg_type_ == TYPE_VALUE_RESPONSE) {
    RELEASE_ASSERT(size == ssize_t(sizeof(ValueResponse) + value_size),
		   "bpfLookup wrong value size");
    // Small values are in &ret, larger values are already at 'value'
    if (buf != value) {
      memcpy(value, buf, value_size);
    }
    return {0, 0};
  }
  RELEASE_ASSERT(resp.msg_type_ == TYPE_SYSCALL_RESPONSE, "bpfLookup invalid response type");
  // Copy syscall response to ret if needed to avoid alignment problems
  if (buf != &ret) {
    memcpy(&ret, buf, sizeof(ret));
  }
  return ret;
}

Envoy::Api::SysCallIntResult setSockOpt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
  auto req = SetSockOptRequest(level, optname, optval, optlen);
  auto resp = SyscallResponse();
  caps.transact(req.hdr_, sizeof(req), nullptr, 0, &sockfd, resp.hdr_, sizeof(resp));
  return resp.ret_;
}
