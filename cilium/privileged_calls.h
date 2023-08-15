#pragma once

#include <string>

#include <sys/types.h>

#include "envoy/api/os_sys_calls_common.h"

// Dump capabilities of the privileged thread into a string
std::string dumpCapabilities();

// Perform a read-only bpf syscall
Envoy::Api::SysCallIntResult bpfOpen(const char *path);
Envoy::Api::SysCallIntResult bpfLookup(int fd, const void *key, uint32_t key_size, void* value, uint32_t value_size);

// Set a privileged socket option
Envoy::Api::SysCallIntResult setSockOpt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
