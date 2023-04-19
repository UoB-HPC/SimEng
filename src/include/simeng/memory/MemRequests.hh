#pragma once

#include "simeng/RegisterValue.hh"

namespace simeng {
namespace memory {

/** A generic memory access target; describes a region of memory to access. */
struct MemoryAccessTarget {
  /** The address to access. */
  uint64_t address;
  /** The number of bytes to access at `address`. */
  uint8_t size;

  /** Check for equality of two access targets. */
  bool operator==(const MemoryAccessTarget& other) const {
    return (address == other.address && size == other.size);
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
                                     uint64_t readyAt)
      : write(true), target(target), data(data), readyAt(readyAt) {}

  /** Construct a read request. */
  FixedLatencyMemoryInterfaceRequest(const MemoryAccessTarget& target,
                                     uint64_t readyAt, uint64_t requestId)
      : write(false), target(target), readyAt(readyAt), requestId(requestId) {}
};

}  // namespace memory
}  // namespace simeng