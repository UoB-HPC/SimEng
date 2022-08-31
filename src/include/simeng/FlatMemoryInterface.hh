#pragma once

#include <vector>

#include "simeng/MemoryInterface.hh"

namespace simeng {

/** A memory interface to a flat memory system. */
class FlatMemoryInterface : public MemoryInterface {
 public:
  FlatMemoryInterface(char* memory, size_t size);

  /** Request a read from the supplied target location.
   *
   * The caller can optionally provide an ID that will be attached to completed
   * read results.
   */
  void requestRead(const MemoryAccessTarget& target,
                   uint64_t requestId = 0) override;
  /** Request a write of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data) override;
  /** Retrieve all completed requests. */
  const span<MemoryReadResult> getCompletedReads() const override;

  /** Clear the completed reads. */
  void clearCompletedReads() override;

  /** Returns true if there are any oustanding memory requests in-flight. */
  bool hasPendingRequests() const override;

  /** Retrieves a pointer to the memory array. */
  char* getMemoryPointer() const override;

  /** Tick: do nothing */
  void tick() override;

 private:
  /** The array representing the flat memory system to access. */
  char* memory_;
  /** The size of accessible memory. */
  size_t size_;
  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;
};

}  // namespace simeng
