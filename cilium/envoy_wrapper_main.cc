#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <unistd.h>
#include <string.h>

#include "cilium/envoy_wrapper_protocol.h"

namespace CiliumEnvoyWrapper {

// WrapperProtocolServer implements the wrapper server.
class WrapperProtocolServer : public WrapperProtocol {
public:
  WrapperProtocolServer(int pid, int pipe);
  ~WrapperProtocolServer();

  void serve();

private:
  // receive buffer type
  union Buffer {
    MessageHeader hdr;
    DumpRequest dump_req;
    BpfOpenRequest bpf_open_req;
    BpfLookupRequest bpf_lookup_req;
    SetSockOptRequest setsockopt_req;
      
    // resposes use the same buffer, so they inherit the message sequence number from the request
    Response response;

    // make space for the largest possible request
    char buf[sizeof(BpfOpenRequest) + PATH_MAX + 1];
  };

  int pid_;  // child pid
};

WrapperProtocolServer::~WrapperProtocolServer() {
  // Wait for cilium-envoy to terminate
  if (pid_ != 0) {
    int rc;
    do {
      rc = ::waitpid(pid_, nullptr, 0);
    } while (rc == -1 && errno == EINTR);
  }
}
  
WrapperProtocolServer::WrapperProtocolServer(int pid, int pipe) :
  WrapperProtocol(pipe), pid_(pid) {
}

void WrapperProtocolServer::serve() {
  Buffer msg = {};

  while (true) {
    // wait for message
    int fd_in;
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
    char *buf = msg.buf + header_size;
    size_t buf_size = sizeof(msg) - header_size;
    size_t value_len = 0; // set below to the actual length of the value to be returned
    int rc = 0;
    int fd_out = -1; // set below when 'rc' is a file descriptor

    switch (msg.hdr.msg_type_) {
    case TYPE_DUMP_REQUEST:
      value_len = dump_capabilities(CAP_EFFECTIVE, buf, buf_size);
      break;
    case TYPE_BPF_OPEN_REQUEST: {
      // zero terminate path name
      msg.bpf_open_req.path_[msg_len - sizeof(msg.bpf_open_req)] = '\0';
      union bpf_attr attr = {};
      attr.pathname = uintptr_t(msg.bpf_open_req.path_);
      fd_out = rc = ::syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
    }
      break;
    case TYPE_BPF_LOOKUP_REQUEST: {
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
    }
      break;
    case TYPE_SETSOCKOPT32_REQUEST:
      rc = ::syscall(__NR_setsockopt, fd_in, msg.setsockopt_req.level_,
		     msg.setsockopt_req.optname_, &msg.setsockopt_req.optval_,
		     sizeof(msg.setsockopt_req.optval_));
      break;
    default:
      IS_ENVOY_BUG(fmt::format("Unexpected privileged call type: {}", msg.hdr.msg_type_));
    }

    // Close the received file descriptor
    if (fd_in != -1) {
      ::close(fd_in);
    }

    // Form the response in place
    msg.response.hdr_.msg_type_ = TYPE_RESPONSE;
    if (fd_out != -1) {
      // Pass a poitive but invalid fd in ret_, to be replaced with the passed
      // fd by the receiver.
      msg.response.ret_ = {INT_MAX, 0};
    } else {
      msg.response.ret_ = {rc, rc != -1 ? 0 : errno};
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

} // namespace CiliumEnvoyWrapper

// NOLINT(namespace-envoy)

#define WRAPPER_SUFFIX "-wrapper"
#define WRAPPER_SUFFIX_LEN (sizeof(WRAPPER_SUFFIX) - 1)

int main(int /* argc */, char** argv) {
  // Check that we have the required capabilities
  uint64_t caps = CiliumEnvoyWrapper::get_capabilities(CAP_EFFECTIVE);
  if ((caps & (1UL << CAP_NET_ADMIN)) == 0 ||
      (caps & (1UL << CAP_SYS_ADMIN | 1UL << CAP_BPF)) == 0) {
    fprintf(stderr, "CAP_NET_ADMIN and either CAP_SYS_ADMIN or CAP_BPF capabilities are needed for Cilium datapath integration.\n");
    exit(1);
  }

  // Get the path we're running from
  char *path = new char[PATH_MAX];
  constexpr size_t path_size = PATH_MAX;
  int path_len = readlink("/proc/self/exe", path, path_size);
  if (path_len < 0 || path_len >= int(path_size)) {
    fprintf(stderr, "could not get path of the current executable: %s\n", strerror(errno));
    exit(1);
  }

  // Remove the trailing "-wrapper" suffix.
  // Check first that the executable name ends in the suffix
  // and is not just the suffix.
  if (size_t(path_len) > WRAPPER_SUFFIX_LEN && // more than suffix in path
      strncmp(path + path_len - WRAPPER_SUFFIX_LEN, WRAPPER_SUFFIX, WRAPPER_SUFFIX_LEN) == 0 &&
      path[path_len - WRAPPER_SUFFIX_LEN - 1] != '/' // slash not the last before suffix
      ) {
    path_len -= WRAPPER_SUFFIX_LEN;
    path[path_len] = '\0';
  } else {
    fprintf(stderr, "Executable name must end in \"" WRAPPER_SUFFIX "\" and not be empty without it: \"%s\"\n", path);
    exit(1);
  }

  int fds[2];
  int rc = socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, fds);
  RELEASE_ASSERT(rc == 0, "socketpair failed");

  int pid = fork();
  RELEASE_ASSERT(pid != -1, "fork failed");

  if (pid == 0) {
    // in child process, close the parent end of the pipe
    close(fds[0]);

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

    RELEASE_ASSERT(CiliumEnvoyWrapper::get_capabilities(CAP_EFFECTIVE) == 0 &&
		   CiliumEnvoyWrapper::get_capabilities(CAP_PERMITTED) == 0 &&
		   CiliumEnvoyWrapper::get_capabilities(CAP_INHERITABLE) == 0,
		   "Failed dropping privileges");

    // Dup the client end to CILIUM_ENVOY_WRAPPER_FD
    if (fds[1] != CILIUM_ENVOY_WRAPPER_FD) {
      if (dup2(fds[1], CILIUM_ENVOY_WRAPPER_FD) < 0) {
	perror("dup2");
	exit(1);
      }
      close(fds[1]);
    }
    
    // Exec cilium-envoy process
    execv(path, argv);
    perror("execv");
    exit(1);
  }
  delete[] path;

  // in parent, close the child end of the pipe
  close(fds[1]);

  // Make sure the child process started
  RELEASE_ASSERT(::waitpid(pid, nullptr, WNOHANG) == 0, "Child process did not start!");

  CiliumEnvoyWrapper::WrapperProtocolServer server(pid, fds[0]);
  server.serve();
  return 0;
}
