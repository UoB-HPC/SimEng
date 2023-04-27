#pragma once

#include <cstdint>

#include "simeng/RegisterValue.hh"

namespace simeng {
namespace memory {

/** A generic memory access target; describes a region of memory to access. */
struct MemoryAccessTarget {
  /** The address to access. */
  uint64_t vaddr = 0;
  /** The number of bytes to access at `address`. */
  uint16_t size = 0;

  /** Constructor to create MemoryAccessTarget with addr and size values. */
  MemoryAccessTarget(uint64_t taddr, uint16_t tsize)
      : vaddr(taddr), size(tsize) {}

  /** Default empty constructor for MemoryAccessTarget. */
  MemoryAccessTarget() {}

  /** Check for equality of two access targets. */
  bool operator==(const MemoryAccessTarget& other) const {
    return (vaddr == other.vaddr && size == other.size);
  };

  /** Check for inequality of two access targets. */
  bool operator!=(const MemoryAccessTarget& other) const {
    return !(other == *this);
  }
};

/** A structure used for the result of memory read operations. */
struct MemoryReadResult {
  /** The memory access that was requested. */
  MemoryAccessTarget target;
  /** The data returned by the request. */
  RegisterValue data;
  /** The request identifier provided by the requester. */
  uint64_t requestId;
};

/** A structure used for the result of conditional store operations. */
struct CondStoreResult {
  /** The request identifier provided by the requester. */
  uint64_t requestId;
  /** Indicates whether the store was successful or not. */
  bool successful;
};

/** A fixed-latency memory interface request. */
struct FixedLatencyMemoryInterfaceRequest {
  /** Is this a write request? */
  bool write;

  /** The memory target to access. */
  const MemoryAccessTarget target;

  /** The value to write to the target (writes only) */
  const RegisterValue data;

  /** The cycle count this request will be ready at. */
  uint64_t readyAt;

  /** A unique request identifier for read operations. */
  uint64_t requestId;

  /** Construct a write request. */
  FixedLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     const RegisterValue& data,
                                     uint64_t readyAt, uint64_t requestId)
      : write(true),
        target(target),
        data(data),
        readyAt(readyAt),
        requestId(requestId) {}

  /** Construct a read request. */
  FixedLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     uint64_t readyAt, uint64_t requestId)
      : write(false), target(target), readyAt(readyAt), requestId(requestId) {}
};

}  // namespace memory
}  // namespace simeng
