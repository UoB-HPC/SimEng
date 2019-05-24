#pragma once

#include "MemoryInterface.hh"

#include <vector>

namespace simeng {

/** A memory interface to a flat memory system. */
class FlatMemoryInterface : public MemoryInterface {
 public:
  FlatMemoryInterface(char* memory, size_t size);

  /** Request a read from the supplied target location. */
  void requestRead(const MemoryAccessTarget& target) override;
  /** Request a write of `data` to the target location. */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data) override;
  /** Retrieve all completed requests. */
  const span<std::pair<MemoryAccessTarget, RegisterValue>> getCompletedReads()
      const override;

  /** Clear the completed reads. */
  void clearCompletedReads() override;

 private:
  /** The array representing the flat memory system to access. */
  char* memory_;
  /** The size of accessible memory. */
  size_t size_;
  /** A vector containing all completed read requests. */
  std::vector<std::pair<MemoryAccessTarget, RegisterValue>> completedReads_;
};

}  // namespace simeng
