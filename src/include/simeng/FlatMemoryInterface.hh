#pragma once

#include <vector>

#include "simeng/MemoryInterface.hh"
#include "simeng/memory/MMU.hh"

namespace simeng {

/** A memory interface to a flat memory system. */
class FlatMemoryInterface : public MemoryInterface {
 public:
  FlatMemoryInterface(std::shared_ptr<memory::MMU> mmu, size_t memSize);

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

  /** Tick: do nothing */
  void tick() override;

 private:
  /** Size of the memory. */
  size_t size_;
  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReads_;
  /**  Shared pointer to the Core MMU */
  std::shared_ptr<simeng::memory::MMU> mmu_;
};

}  // namespace simeng
