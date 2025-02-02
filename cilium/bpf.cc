#include "cilium/bpf.h"

#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>

#include "source/common/common/logger.h"
#include "source/common/common/utility.h"

#include "cilium/privileged_service_client.h"
#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

enum {
  BpfKeyMaxLen = 64,
};

Bpf::Bpf(uint32_t map_type, uint32_t key_size, uint32_t min_value_size, uint32_t max_value_size)
    : fd_(-1), map_type_(map_type), key_size_(key_size), min_value_size_(min_value_size),
      max_value_size_(max_value_size), real_value_size_(0) {
  if (max_value_size_ == 0) {
    max_value_size_ = min_value_size_;
  }
}

Bpf::~Bpf() { close(); }

void Bpf::close() {
  if (fd_ >= 0) {
    ::close(fd_);
  }
  fd_ = -1;
  real_value_size_ = 0;
}

bool Bpf::open(const std::string& path) {
  bool log_on_error = ENVOY_LOG_CHECK_LEVEL(trace);

  // close old fd if any
  close();

  // store the path for later
  if (path != path_) {
    path_ = path;
  }

  auto& cilium_calls = PrivilegedService::Singleton::get();
  auto ret = cilium_calls.bpfOpen(path.c_str());
  fd_ = ret.return_value_;
  if (fd_ >= 0) {
    // Open fdinfo to check the map type and key and value size.
    std::string line;
    std::string bpf_file_path("/proc/" + std::to_string(getpid()) + "/fdinfo/" +
                              std::to_string(fd_));
    std::ifstream bpf_file(bpf_file_path);
    if (bpf_file.is_open()) {
      uint32_t map_type = UINT32_MAX, key_size = UINT32_MAX, value_size = UINT32_MAX;

      while (std::getline(bpf_file, line)) {
        std::istringstream iss(line);
        std::string tag;

        if (std::getline(iss, tag, ':')) {
          unsigned int value;

          if (iss >> value) {
            if (tag == "map_type") {
              map_type = value;
            } else if (tag == "key_size") {
              key_size = value;
            } else if (tag == "value_size") {
              value_size = value;
            }
          }
        }
      }
      bpf_file.close();

      if ((map_type == map_type_ ||
           (map_type == BPF_MAP_TYPE_LRU_HASH && map_type_ == BPF_MAP_TYPE_HASH)) &&
          key_size == key_size_ && min_value_size_ <= value_size && value_size <= max_value_size_) {
        // keep the actual value size.
        real_value_size_ = value_size;
        return true;
      }
      if (log_on_error) {
        if (map_type != map_type_) {
          ENVOY_LOG(warn, "cilium.bpf_metadata: map type mismatch on {}: got {}, wanted {}", path,
                    map_type, map_type_);
        } else if (key_size != key_size_) {
          ENVOY_LOG(warn,
                    "cilium.bpf_metadata: map key size mismatch on {}: got {}, "
                    "wanted {}",
                    path, key_size, key_size_);
        } else {
          ENVOY_LOG(warn,
                    "cilium.bpf_metadata: map value size mismatch on {}: got "
                    "{}, wanted {}-{}",
                    path, value_size, min_value_size_, max_value_size_);
        }
      }
    } else if (log_on_error) {
      ENVOY_LOG(warn, "cilium.bpf_metadata: map {} could not open bpf file {}", path,
                bpf_file_path);
    }
    close();
  } else if (ret.errno_ == ENOENT && log_on_error) {
    ENVOY_LOG(debug, "cilium.bpf_metadata: bpf syscall for map {} failed: {}", path,
              Envoy::errorDetails(ret.errno_));
  } else if (log_on_error) {
    ENVOY_LOG(warn, "cilium.bpf_metadata: bpf syscall for map {} failed: {}", path,
              Envoy::errorDetails(ret.errno_));
  }

  errno = ret.errno_;

  return false;
}

// value must point to space of at least 'max_value_size_' as passed in to the constructor.
bool Bpf::lookup(const void* key, void* value) {
  // Try reopen if open failed previously
  if (fd_ < 0) {
    if (!open(path_)) {
      return false;
    }
  }

  auto& cilium_calls = PrivilegedService::Singleton::get();
  auto result = cilium_calls.bpfLookup(fd_, key, key_size_, value, real_value_size_);

  if (result.return_value_ == 0) {
    return true;
  }

  errno = result.errno_;
  return false;
}

} // namespace Cilium
} // namespace Envoy
