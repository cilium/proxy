#if !defined(__linux__)
#error "Linux platform file is part of non-Linux build."
#endif

#include <errno.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include "starter/privileged_service_server.h"

// NOLINT(namespace-envoy)

#define STARTER_SUFFIX "-starter"
#define STARTER_SUFFIX_LEN (sizeof(STARTER_SUFFIX) - 1)

int main(int /* argc */, char** argv) {
  // Check that we have the required capabilities
  uint64_t caps = Envoy::Cilium::PrivilegedService::get_capabilities(CAP_EFFECTIVE);
  if ((caps & (1UL << CAP_NET_ADMIN)) == 0 ||
      (caps & (1UL << CAP_SYS_ADMIN | 1UL << CAP_BPF)) == 0) {
    fprintf(stderr, "CAP_NET_ADMIN and either CAP_SYS_ADMIN or CAP_BPF capabilities are needed for "
                    "Cilium datapath integration.\n");
    exit(1);
  }

  // Get the path we're running from
  char* path = new char[PATH_MAX];
  constexpr size_t path_size = PATH_MAX;
  int path_len = readlink("/proc/self/exe", path, path_size);
  if (path_len < 0 || path_len >= int(path_size)) {
    fprintf(stderr, "could not get path of the current executable: %s\n", strerror(errno));
    exit(1);
  }

  // Remove the trailing "-starter" suffix.
  // Check first that the executable name ends in the suffix
  // and is not just the suffix.
  if (size_t(path_len) > STARTER_SUFFIX_LEN && // more than suffix in path
      strncmp(path + path_len - STARTER_SUFFIX_LEN, STARTER_SUFFIX, STARTER_SUFFIX_LEN) == 0 &&
      path[path_len - STARTER_SUFFIX_LEN - 1] != '/' // slash not the last before suffix
  ) {
    path_len -= STARTER_SUFFIX_LEN;
    path[path_len] = '\0';
  } else {
    fprintf(stderr,
            "Executable name must end in \"" STARTER_SUFFIX
            "\" and not be empty without it: \"%s\"\n",
            path);
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
    struct __user_cap_header_struct hdr {
      _LINUX_CAPABILITY_VERSION_3, 0
    };
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

    RELEASE_ASSERT(Envoy::Cilium::PrivilegedService::get_capabilities(CAP_EFFECTIVE) == 0 &&
                       Envoy::Cilium::PrivilegedService::get_capabilities(CAP_PERMITTED) == 0 &&
                       Envoy::Cilium::PrivilegedService::get_capabilities(CAP_INHERITABLE) == 0,
                   "Failed dropping privileges");

    // Dup the client end to CILIUM_PRIVILEGED_SERVICE_FD
    if (fds[1] != CILIUM_PRIVILEGED_SERVICE_FD) {
      if (dup2(fds[1], CILIUM_PRIVILEGED_SERVICE_FD) < 0) {
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

  Envoy::Cilium::PrivilegedService::ProtocolServer server(pid, fds[0]);
  server.serve();
  return 0;
}
