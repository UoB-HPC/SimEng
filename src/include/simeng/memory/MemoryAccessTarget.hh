#pragma once

namespace simeng {

namespace memory {

/** A generic memory access target; describes a region of memory to access. */
struct MemoryAccessTarget {
  /** The address to access. */
  uint64_t address;
  /** The number of bytes to access at `address`. */
  uint16_t size;

  /** Check for equality of two access targets. */
  bool operator==(const MemoryAccessTarget& other) const {
    return (address == other.address && size == other.size);
  };

  /** Check for inequality of two access targets. */
  bool operator!=(const MemoryAccessTarget& other) const {
    return !(other == *this);
  }
};

}  // namespace memory
}  // namespace simeng