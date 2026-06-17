#pragma once

#include <cstdint>

#include "simeng/RegisterValue.hh"

namespace simeng {
namespace memory {

enum class pendingState {
  NONE = 0,
  WAITING,
  COMPLETE,
};

/** A generic memory access target; describes a region of memory to access. */
struct MemoryAccessTarget {
  /** The address to access. */
  uint64_t vaddr = 0;
  /** The number of bytes to access at `address`. */
  uint32_t size = 0;

  uint64_t id = 0;

  uint64_t forwarder = 0;

  bool missedCache_ = false;
  bool reSubmittedMem_ = false;
  bool shouldMIMO_ = false;
  pendingState pendingTranslation_ = pendingState::NONE;

  std::vector<uint64_t> clsAccessed_ = {};

  uint64_t cycleMemSent_ = 0;
  uint64_t cycleMemRecv_ = 0;

  /** Constructor to create MemoryAccessTarget with addr and size values. */
  MemoryAccessTarget(uint64_t taddr, uint32_t tsize)
      : vaddr(taddr), size(tsize) {}

  /** Constructor to create MemoryAccessTarget with addr and size values. */
  MemoryAccessTarget(uint64_t taddr, uint32_t tsize, uint64_t tid)
      : vaddr(taddr), size(tsize), id(tid) {}

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

}  // namespace memory
}  // namespace simeng
