#include "simeng/FlatMemoryInterface.hh"

#include <cassert>
#include <iostream>

namespace simeng {

FlatMemoryInterface::FlatMemoryInterface(std::shared_ptr<memory::MMU> mmu)
    : mmu_(mmu) {}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                      uint64_t requestId) {
  // Instantiate a callback function which will be invoked with the response
  // to a read request.
  auto fn = [this, target,
             requestId](std::unique_ptr<memory::MemPacket> packet) -> void {
    if (packet->isFaulty()) {
      completedReads_.push_back({target, RegisterValue(), requestId});
      return;
    }
    completedReads_.push_back(
        {target, RegisterValue(packet->data().data(), packet->size_),
         requestId});
  };

  mmu_->bufferRequest(memory::MemPacket::createReadRequest(
                          target.address, target.size, requestId),
                      fn);
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);
  // Responses to write requests are ignored by passing in a nullptr
  // callback because they don't contain any information relevant to the
  // simulation.
  mmu_->bufferRequest(
      memory::MemPacket::createWriteRequest(target.address, target.size, 0, dt),
      nullptr);
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
