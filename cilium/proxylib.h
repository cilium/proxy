#pragma once

#include <google/protobuf/map.h>

#include <cstdint>
#include <memory>
#include <string>

#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"

#include "proxylib/libcilium.h"
#include "proxylib/types.h"

namespace Envoy {
namespace Cilium {

struct GoString {
  GoString(const std::string& str) : mem_(str.c_str()), len_(str.length()) {}
  GoString() : mem_(nullptr), len_(0) {}

  const char* mem_;
  GoInt len_;
};

template <typename T> struct GoSlice {
  GoSlice() : data_(nullptr), len_(0) {}
  GoSlice(T* data, GoInt len) : data_(data), len_(len), cap_(len) {} // Initialized as full
  GoInt len() const { return len_; }
  GoInt cap() const { return cap_; }
  T& operator[](GoInt x) { return data_[x]; }
  const T& operator[](GoInt x) const { return data_[x]; }
  operator T*() { return data_; }
  operator const T*() const { return data_; }
  operator void*() { return data_; }
  operator const void*() const { return data_; }

  T* data_;
  GoInt len_;
  GoInt cap_;
};

inline std::string toString(const FilterResult res) {
  switch (res) {
  case FILTER_OK:
    return "No error";
  case FILTER_PARSER_ERROR:
    return "Parser error";
  case FILTER_UNKNOWN_CONNECTION:
    return "Unknown connection";
  case FILTER_UNKNOWN_PARSER:
    return "Unknown parser";
  case FILTER_INVALID_ADDRESS:
    return "Invalid address";
  case FILTER_POLICY_DROP:
    return "Connection rejected";
  case FILTER_INVALID_INSTANCE:
    return "Invalid proxylib instance";
  case FILTER_UNKNOWN_ERROR:
    break;
  }
  return "Unknown error";
}

// Slice that remembers the base pointer and that can be reset.
// Note that these have more header data than GoSlices and therefore may not
// used as array elements passed to Go!
template <typename T> struct ResetableSlice : GoSlice<T> {
  // Templated base class member access is a bit ugly
  using GoSlice<T>::data_;
  using GoSlice<T>::len_;
  using GoSlice<T>::cap_;

  ResetableSlice(T* data, GoInt cap) : GoSlice<T>(data, cap), base_(data) {
    len_ = 0; // Init as empty
  }

  // Non-Go helpers to consume data filled in by Go. Must reset() before slice
  // used by Go again.
  GoInt drain(GoInt len) {
    if (len > len_) {
      len = len_;
    }
    data_ += len;
    len_ -= len;

    return len;
  }
  bool at_capacity() {
    // Return true if all of the available space was used, not affected by
    // draining
    return (data_ + len_) >= (base_ + cap_);
  }
  void reset() {
    data_ = base_;
    len_ = 0;
  }

  // private part not visible to Go
  T* base_;
};

struct GoStringPair {
  GoString key;
  GoString value;
};

using GoKeyValueSlice = GoSlice<GoStringPair>;
using GoOpenModuleCB = uint64_t (*)(GoKeyValueSlice, bool);
using GoCloseModuleCB = void (*)(uint64_t);

using GoBufferSlice = ResetableSlice<uint8_t>;
using GoOnNewConnectionCB = FilterResult (*)(uint64_t, GoString, uint64_t, bool, uint32_t, uint32_t,
                                             GoString, GoString, GoString, GoBufferSlice*,
                                             GoBufferSlice*);

using GoDataSlices = GoSlice<GoSlice<uint8_t>>; // Scatter-gather buffer list as '[][]byte'
using GoFilterOpSlice = ResetableSlice<FilterOp>;
using GoOnDataCB = FilterResult (*)(uint64_t, bool, bool, GoDataSlices*, GoFilterOpSlice*);
using GoCloseCB = void (*)(uint64_t);

class GoFilter : public Logger::Loggable<Logger::Id::filter> {
public:
  GoFilter(const std::string& go_module, const Protobuf::Map<::std::string, ::std::string>&);
  ~GoFilter();

  class Instance : public Logger::Loggable<Logger::Id::filter> {
  public:
    Instance(const GoFilter& parent, Network::Connection& conn) : parent_(parent), conn_(conn) {}
    ~Instance() {
      if (connection_id_) {
        // Tell Go parser to scrap the state kept for the connection
        (*parent_.go_close_)(connection_id_);
      }
    }

    void Close();

    FilterResult OnIO(bool reply, Buffer::Instance& data, bool end_stream);

    bool WantReplyInject() const { return reply_.WantToInject(); }
    void SetOrigEndStream(bool end_stream) { orig_.closed_ = end_stream; }
    void SetReplyEndStream(bool end_stream) { reply_.closed_ = end_stream; }

    struct Direction {
      Direction() : inject_slice_(inject_buf_, sizeof(inject_buf_)) {}

      bool WantToInject() const { return !closed_ && inject_slice_.len() > 0; }
      void Close() { closed_ = true; }

      Buffer::OwnedImpl buffer_; // Buffered data in this direction
      int64_t need_bytes_{0};    // Number of additional data bytes needed before can parse again
      int64_t pass_bytes_{0};    // Number of bytes to pass without calling the parser again
      int64_t drop_bytes_{0};
      bool closed_{false};
      GoBufferSlice inject_slice_;
      uint8_t inject_buf_[1024];
    };

    const GoFilter& parent_;
    Network::Connection& conn_;
    Direction orig_;
    Direction reply_;
    uint64_t connection_id_ = 0;
  };
  using InstancePtr = std::unique_ptr<Instance>;

  InstancePtr NewInstance(Network::Connection& conn, const std::string& go_proto, bool ingress,
                          uint32_t src_id, uint32_t dst_id, const std::string& src_addr,
                          const std::string& dst_addr, const std::string& policy_name) const;

private:
  void* go_module_handle_{nullptr};
  GoCloseModuleCB go_close_module_;
  GoOnNewConnectionCB go_on_new_connection_;
  GoOnDataCB go_on_data_;
  GoCloseCB go_close_;
  uint64_t go_module_id_{0};
};

using GoFilterSharedPtr = std::shared_ptr<const GoFilter>;

} // namespace Cilium
} // namespace Envoy
