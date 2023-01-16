#include "simeng/FlatMemoryInterface.hh"

#include <cassert>
#include <iostream>

namespace simeng {

FlatMemoryInterface::FlatMemoryInterface(
    std::shared_ptr<simeng::memory::Mem> memory) {
  memory_ = memory;
  size_ = memory_->getMemorySize();
}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                      uint64_t requestId) {
  if (target.address + target.size > size_) {
    // Read outside of memory; return an invalid value to signal a fault
    completedReads_.push_back({target, RegisterValue(), requestId});
    return;
  }

  simeng::memory::ReadRespPacket* resp =
      (simeng::memory::ReadRespPacket*)memory_->requestAccess(
          new simeng::memory::ReadPacket(target.address, target.size));

  // Copy the data at the requested memory address into a RegisterValue
  completedReads_.push_back(
      {target, RegisterValue(resp->data, resp->bytesRead), requestId});
  delete resp;
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  assert(target.address + target.size <= size_ &&
         "Attempted to write beyond memory limit");

  simeng::memory::WriteRespPacket* resp =
      (simeng::memory::WriteRespPacket*)memory_->requestAccess(
          new simeng::memory::WritePacket(target.address, target.size,
                                          data.getAsVector<char>()));
  delete resp;
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
