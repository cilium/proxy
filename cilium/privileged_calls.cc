#include "cilium/privileged_calls.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>

#include "linux/bpf.h"

#include "absl/types/variant.h"

#include "source/common/common/assert.h"

struct DumpCapabilities {
  std::string output_ = "";

  DumpCapabilities() {}
};

struct BpfSyscall {
  int cmd_;
  union bpf_attr* attr_;
  Envoy::Api::SysCallIntResult ret_{0, 0};

  BpfSyscall(int cmd, union bpf_attr* attr) : cmd_(cmd), attr_(attr) {}
};

struct SetSockOpt {
  int sockfd_;
  int level_;
  int optname_;
  const void* optval_;
  socklen_t optlen_;
  Envoy::Api::SysCallIntResult ret_{0, 0};

  SetSockOpt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
    : sockfd_(sockfd), level_(level), optname_(optname), optval_(optval), optlen_(optlen) {}
};

typedef absl::variant<DumpCapabilities, BpfSyscall, SetSockOpt> PrivilegedCall;

// call_mutex is taken by the calling side to serialize full call roundtrips
pthread_mutex_t call_mutex = PTHREAD_MUTEX_INITIALIZER;
// msg must be nullptr when call_mutex is not held!
PrivilegedCall *msg = nullptr;
pthread_cond_t    msg_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;

void msg_signal(PrivilegedCall *m) {
  RELEASE_ASSERT(!msg == !!m, "privileged call protocol error!");
  msg = m;

  int rc = pthread_mutex_lock(&cond_mutex);
  if (rc != 0) {
    printf("pthread_mutex_lock: %s\n", strerror(rc));
    exit(1);
  }

  rc = pthread_cond_signal(&msg_cond);
  if (rc != 0) {
    printf("pthread_cond_broadcast: %s\n", strerror(rc));
    exit(1);
  }

  rc = pthread_mutex_unlock(&cond_mutex);
  if (rc != 0) {
    printf("pthread_mutex_unlock: %s\n", strerror(rc));
    exit(1);
  }
}

PrivilegedCall* msg_wait(bool set) {
  // wait for the respose
  int rc = pthread_mutex_lock(&cond_mutex);
  if (rc != 0) {
    printf("pthread_mutex_lock: %s\n", strerror(rc));
    exit(1);
  }

  // block while msg is nullprt if !set, or while msg is not nullptr if set 
  while (!msg == set) {
    rc = pthread_cond_wait(&msg_cond, &cond_mutex);
    if (rc != 0) {
      printf("pthread_cond_wait: %s\n", strerror(rc));
      exit(1);
    }
  }

  rc = pthread_mutex_unlock(&cond_mutex);
  if (rc != 0) {
    printf("pthread_mutex_unlock: %s\n", strerror(rc));
    exit(1);
  }

  return msg;
}

void privilegedCall(PrivilegedCall& call_msg) {
  // Serialize privileged calls
  int rc = pthread_mutex_lock(&call_mutex);
  if (rc != 0) {
    printf("pthread_mutex_lock: %s\n", strerror(rc));
    exit(1);
  }
  msg_signal(&call_msg);

  // wait for the respose
  msg_wait(false);
  RELEASE_ASSERT(msg == nullptr, "privileged call protocol error, msg must be nullptr!");
  
  rc = pthread_mutex_unlock(&call_mutex);
  if (rc != 0) {
    printf("pthread_mutex_unlock: %s\n", strerror(rc));
    exit(1);
  }
}

std::string dumpCapabilities() {
  PrivilegedCall call = DumpCapabilities();
  privilegedCall(call);
  
  return absl::get<DumpCapabilities>(call).output_;
}

int bpfSyscall(int cmd, union bpf_attr* attr) {
  PrivilegedCall call = BpfSyscall(cmd, attr);
  privilegedCall(call);
  return absl::get<BpfSyscall>(call).ret_.return_value_;
}

Envoy::Api::SysCallIntResult setSockOpt(int sockfd, int level, int optname, const void* optval, socklen_t optlen) {
  PrivilegedCall call = SetSockOpt(sockfd, level, optname, optval, optlen);
  privilegedCall(call);
  return absl::get<SetSockOpt>(call).ret_;
}

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

static void dumpCaps(cap_flag_t kind, std::string& output) {
  struct __user_cap_header_struct hdr{_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct data[2];
  memset(&data, 0, sizeof(data));
  int rc = ::syscall(SYS_capget, &hdr, &data, sizeof(data));
  if (rc != 0) {
    printf("capget() failed: %s\n", strerror(errno));
    exit(1);
  }

  uint64_t caps = 0;
  switch (kind) {
  case CAP_EFFECTIVE:
    caps = data[0].effective | uint64_t(data[1].effective) << 32;
    break;
  case CAP_PERMITTED:
    caps = data[0].permitted | uint64_t(data[1].permitted) << 32;
    break;
  case CAP_INHERITABLE:
    caps = data[0].inheritable | uint64_t(data[1].inheritable) << 32;
    break;
  default:
    printf("invalid capability kind: %d", kind);
    exit(1);
  }

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
}

static void * privileged_thread(void *) {
  // Bpf needs relaxed limits on memory
  struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
  int ret = setrlimit(RLIMIT_MEMLOCK, &rl);
  if (ret != 0) {
    printf("setrlimit(RLIMIT_MEMLOCK) failed: %s\n", strerror(errno));
  }

  while (true) {
    // wait for message
    auto& m = *msg_wait(true);

    if (absl::holds_alternative<DumpCapabilities>(m)) {
      auto& call = absl::get<DumpCapabilities>(m);
      dumpCaps(CAP_EFFECTIVE, call.output_);
    } else if (absl::holds_alternative<BpfSyscall>(m)) { 
      auto& call = absl::get<BpfSyscall>(m);
      switch (call.cmd_) {
      case BPF_OBJ_GET:
      case BPF_MAP_LOOKUP_ELEM:
	// Only lookups are allowed!
	call.ret_.return_value_ = ::syscall(__NR_bpf, call.cmd_, call.attr_, sizeof(*call.attr_));
	call.ret_.errno_ = errno;
	break;
      default:
	call.ret_.return_value_ = -1;
	call.ret_.errno_ = EPERM;
	break;
      }
    } else if (absl::holds_alternative<SetSockOpt>(m)) { 
      auto& call = absl::get<SetSockOpt>(m);
      call.ret_.return_value_ = ::syscall(__NR_setsockopt, call.sockfd_, call.level_, call.optname_, call.optval_, call.optlen_);
      call.ret_.errno_ = errno;
    } else {
      printf("Unknown privileged call type\n");
    }

    msg_signal(nullptr);
  }

  return nullptr;
}

static pthread_t thread_handle;

static int dropCaps() {
  int rc = pthread_create(&thread_handle, nullptr, privileged_thread, nullptr);
  RELEASE_ASSERT(rc == 0, "pthread_create failed");

  struct __user_cap_header_struct hdr{_LINUX_CAPABILITY_VERSION_3, 0};
  struct __user_cap_data_struct data[2];
  memset(&data, 0, sizeof(data));
  rc = ::syscall(SYS_capset, &hdr, &data, sizeof(data));
  if (rc != 0) {
    printf("capset() failed: %s\n", strerror(errno));
    exit(1);
  }
  
  // Drop bounding set to prevent regaining dropped capabilities
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    perror("prctl PR_SET_NO_NEW_PRIVS");
    exit(1);
  }

  std::string effective;
  dumpCaps(CAP_EFFECTIVE, effective);
  std::string permitted;
  dumpCaps(CAP_PERMITTED, permitted);

  if (effective.length() > 0 && permitted.length() > 0) {
    printf("Dropping capabilities failed: effective: %s, permitted: %s\n",
	   effective.c_str(), permitted.c_str());
    exit(1);
  }

  auto output = dumpCapabilities();
  printf("Capabilities dropped successfully, privileged thread started with capabilities: %s\n",
	 output.c_str());

  return output.length() == 0;
}

const auto caps = dropCaps();

