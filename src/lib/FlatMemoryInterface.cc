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
  auto fn = [&, this](memory::ReadResponse dpkt) -> void {
    if (dpkt.address_ == ~(uint64_t)0) {
      this->completedReads_.push_back({target, RegisterValue(), requestId});
      return;
    }
    this->completedReads_.push_back(
        {target, RegisterValue(dpkt.data().begin(), dpkt.size_), requestId});
  };

  mmu_->bufferRequest(memory::ReadRequest(target.address, target.size), fn);
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  auto fn = [&](memory::WriteResponse dpkt) -> void {};

  const char* wdata = data.getAsVector<char>();
  memory::WriteRequest req{target.address, target.size};
  std::copy(wdata, wdata + target.size, req.data().begin());
  mmu_->bufferRequest(req, fn);
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
