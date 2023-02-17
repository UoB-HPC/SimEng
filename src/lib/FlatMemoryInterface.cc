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
  auto fn = [&, this](memory::DataPacket* dpkt = NULL) -> void {
    if (dpkt == NULL) {
      // Sending an empty RegisterValue here signifies a data abort exception as
      // a response wasn't recieved from memory.
      this->completedReads_.push_back({target, RegisterValue(), requestId});
      return;
    }
    memory::ReadRespPacket* resp = (memory::ReadRespPacket*)dpkt;
    this->completedReads_.push_back(
        {target, RegisterValue(resp->data, resp->bytesRead), requestId});
    delete resp;
  };

  mmu_->bufferRequest(new memory::ReadPacket(target.address, target.size), fn);
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  auto fn = [&](memory::DataPacket* dpkt = NULL) -> void {
    if (dpkt == NULL) return;
    // If dpkt is not null the response is ignored as it doesn't contain any
    // information relevant after the write has completed.
    delete dpkt;
  };

  const char* wdata = data.getAsVector<char>();
  mmu_->bufferRequest(
      new simeng::memory::WritePacket(target.address, target.size, wdata), fn);
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
