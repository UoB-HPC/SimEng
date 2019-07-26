#include "simeng/FlatMemoryInterface.hh"

#include <cassert>

namespace simeng {

FlatMemoryInterface::FlatMemoryInterface(char* memory, size_t size)
    : memory_(memory), size_(size) {}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target) {
  if (target.address + target.size > size_) {
    // Read outside of memory; return an invalid value to signal a fault
    completedReads_.push_back({target, RegisterValue()});
    return;
  }

  const char* ptr = memory_ + target.address;

  // Copy the data at the requested memory address into a RegisterValue
  completedReads_.push_back({target, RegisterValue(ptr, target.size)});
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  assert(target.address + target.size <= size_ &&
         "Attempted to write beyond memory limit");

  auto ptr = memory_ + target.address;
  // Copy the data from the RegisterValue to memory
  memcpy(ptr, data.getAsVector<char>(), target.size);
}

const span<std::pair<MemoryAccessTarget, RegisterValue>>
FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<std::pair<MemoryAccessTarget, RegisterValue>*>(
              completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
