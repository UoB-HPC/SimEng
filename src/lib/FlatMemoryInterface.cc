#include "simeng/FlatMemoryInterface.hh"

#include <cassert>
#include <iostream>

namespace simeng {

FlatMemoryInterface::FlatMemoryInterface(std::shared_ptr<memory::MMU> mmu,
                                         size_t memSize) {
  mmu_ = mmu;
  size_ = memSize;
}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                      uint64_t requestId) {
  if (target.address + target.size > size_) {
    // Read outside of memory; return an invalid value to signal a fault
    completedReads_.push_back({target, RegisterValue(), requestId});
    return;
  }

  auto fn = [&, this](memory::DataPacket* dpkt) -> void {
    if (dpkt == NULL) {
      return;
    }
    memory::ReadRespPacket* resp = (memory::ReadRespPacket*)dpkt;
    this->completedReads_.push_back(
        {target, RegisterValue(resp->data, resp->bytesRead), requestId});
    delete resp;
  };

  mmu_->bufferRequest(new memory::ReadPacket(target.address, target.size), fn);

  // Copy the data at the requested memory address into a RegisterValue
  // completedReads_.push_back(
  // {target, RegisterValue(resp->data, resp->bytesRead), requestId});
  // delete resp;
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  /*
assert(target.address + target.size <= size_ &&
       "Attempted to write beyond memory limit");
       */

  auto fn = [&](memory::DataPacket* dpkt) -> void {
    if (dpkt == NULL) return;
    delete dpkt;
  };

  const char* wdata = data.getAsVector<char>();
  mmu_->bufferRequest(
      new simeng::memory::WritePacket(target.address, target.size, wdata), fn);
  /*
  simeng::memory::WriteRespPacket* resp =
      (simeng::memory::WriteRespPacket*)memory_->requestAccess(
          new simeng::memory::WritePacket(target.address, target.size,
                                         data.getAsVector<char>()));
  delete resp;
  */
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
