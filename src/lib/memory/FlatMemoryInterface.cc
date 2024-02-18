#include "simeng/memory/FlatMemoryInterface.hh"

#include <iostream>

namespace simeng {

namespace memory {

FlatMemoryInterface::FlatMemoryInterface(char* memory, size_t size)
    : memory_(memory), size_(size) {}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                      uint64_t requestId) {
  if (target.address + target.size > size_) {
    // Read outside of memory; return an invalid value to signal a fault
    completedReads_.push_back({target, RegisterValue(), requestId});
    return;
  }

  const char* ptr = memory_ + target.address;

  // Copy the data at the requested memory address into a RegisterValue
  completedReads_.push_back(
      {target, RegisterValue(ptr, target.size), requestId});
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  if (target.address + target.size > size_) {
    std::cerr << "[SimEng:FlatLatencyMemoryInterface] Attempted to write "
                 "beyond memory limit."
              << std::endl;
    exit(1);
  }

  auto ptr = memory_ + target.address;
  // Copy the data from the RegisterValue to memory
  memcpy(ptr, data.getAsVector<char>(), target.size);
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace memory
}  // namespace simeng
