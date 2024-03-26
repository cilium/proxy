#include "cilium/bpf.h"

#include <errno.h>

#include "source/common/common/utility.h"

#include "cilium/privileged_service_client.h"
#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

enum {
  BPF_KEY_MAX_LEN = 64,
};

Bpf::Bpf(uint32_t map_type, uint32_t key_size, uint32_t value_size)
    : fd_(-1), map_type_(map_type), key_size_(key_size), value_size_(value_size) {}

Bpf::~Bpf() { close(); }

void Bpf::close() {
  if (fd_ >= 0)
    ::close(fd_);
  fd_ = -1;
}

bool Bpf::open(const std::string& path) {
  bool log_on_error = ENVOY_LOG_CHECK_LEVEL(trace);

  auto& cilium_calls = PrivilegedService::Singleton::get();
  auto ret = cilium_calls.bpf_open(path.c_str());
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
          key_size == key_size_ && value_size == value_size_) {
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
                    "{}, wanted {}",
                    path, value_size, value_size_);
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

bool Bpf::lookup(const void* key, void* value) {
  auto& cilium_calls = PrivilegedService::Singleton::get();
  auto result = cilium_calls.bpf_lookup(fd_, key, key_size_, value, value_size_);

  if (result.return_value_ == 0) {
    return true;
  }

  errno = result.errno_;
  return false;
}

} // namespace Cilium
} // namespace Envoy
