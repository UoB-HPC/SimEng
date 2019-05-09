#pragma once

#include "RegisterValue.hh"
#include "span.hh"

namespace simeng {

/** A generic memory access target; describes a region of memory to access. */
struct MemoryAccessTarget {
  /** The address to access. */
  uint64_t address;
  /** The number of bytes to access at `address`. */
  uint8_t size;
};

/** An abstract memory interface. Describes a connection to a memory system to
 * which data read/write requests may be made. */
class MemoryInterface {
 public:
  /** Request a read from the supplied target location. */
  virtual void requestRead(const MemoryAccessTarget& target) = 0;
  /** Request a write of `data` to the target location. */
  virtual void requestWrite(const MemoryAccessTarget& target,
                            const RegisterValue& data) = 0;
  /** Retrieve all completed requests. */
  virtual span<std::pair<MemoryAccessTarget, RegisterValue>> getCompletedReads()
      const = 0;
};

}  // namespace simeng
