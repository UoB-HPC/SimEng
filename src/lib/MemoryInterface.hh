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

  /** Check for equality of two access targets. */
  bool operator==(const MemoryAccessTarget& other) const {
    return (address == other.address && size == other.size);
  };

  /** Check for inequality of two access targets. */
  bool operator!=(const MemoryAccessTarget& other) const {
    return !(other == *this);
  }
};

/** An abstract memory interface. Describes a connection to a memory system to
 * which data read/write requests may be made. */
class MemoryInterface {
 public:
  virtual ~MemoryInterface() {}

  /** Request a read from the supplied target location. */
  virtual void requestRead(const MemoryAccessTarget& target) = 0;
  /** Request a write of `data` to the target location. */
  virtual void requestWrite(const MemoryAccessTarget& target,
                            const RegisterValue& data) = 0;
  /** Retrieve all completed read requests. */
  virtual const span<std::pair<MemoryAccessTarget, RegisterValue>>
  getCompletedReads() const = 0;

  /** Clear the completed reads. */
  virtual void clearCompletedReads() = 0;

  /** Tick the memory interface to allow it to process internal tasks.
   *
   * TODO: Move ticking out of the memory interface and into a central "memory
   * system" covering a set of related interfaces.
   */
  virtual void tick() = 0;
};

}  // namespace simeng
