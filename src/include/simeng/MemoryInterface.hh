#pragma once

#include "simeng/RegisterValue.hh"
#include "simeng/span.hh"

namespace simeng {

/** The available memory interface types. */
enum class MemInterfaceType {
  Flat,     // A zero access latency interface
  Fixed,    // A fixed, non-zero, access latency interface
  External  // An interface generated outside of the standard SimEng
            // instantiation
};

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

/** A structure used for the result of memory read operations. */
struct MemoryReadResult {
  /** The memory access that was requested. */
  MemoryAccessTarget target;
  /** The data returned by the request. */
  RegisterValue data;
  /** The request identifier provided by the requester. */
  uint64_t requestId;
};

/** An abstract memory interface. Describes a connection to a memory system to
 * which data read/write requests may be made. */
class MemoryInterface {
 public:
  virtual ~MemoryInterface() {}

  /** Request a read from the supplied target location.
   *
   * The caller can optionally provide an ID that will be attached to completed
   * read results.
   */
  virtual void requestRead(const MemoryAccessTarget& target,
                           uint64_t requestId = 0) = 0;
  /** Request a write of `data` to the target location. */
  virtual void requestWrite(const MemoryAccessTarget& target,
                            const RegisterValue& data) = 0;
  /** Retrieve all completed read requests. */
  virtual const span<MemoryReadResult> getCompletedReads() const = 0;

  /** Clear the completed reads. */
  virtual void clearCompletedReads() = 0;

  /** Returns true if there are any outstanding memory requests in-flight. */
  virtual bool hasPendingRequests() const = 0;

  /** Tick the memory interface to allow it to process internal tasks.
   *
   * TODO: Move ticking out of the memory interface and into a central "memory
   * system" covering a set of related interfaces.
   */
  virtual void tick() = 0;
};

}  // namespace simeng
