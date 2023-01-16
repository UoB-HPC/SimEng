#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(
    std::shared_ptr<simeng::memory::Mem> memory, uint16_t latency)
    : memory_(memory), latency_(latency), size_(memory->getMemorySize()) {}

void FixedLatencyMemoryInterface::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      break;
    }

    const auto& target = request.target;

    if (request.write) {
      // Write: write data directly to memory
      assert(target.address + target.size <= memory_->getMemorySize() &&
             "Attempted to write beyond memory limit");

      simeng::memory::WriteRespPacket* resp =
          (simeng::memory::WriteRespPacket*)memory_->requestAccess(
              new simeng::memory::WritePacket{
                  target.address, target.size,
                  request.data.getAsVector<char>()});
      delete resp;
    } else {
      // Read: read data into `completedReads`
      if (target.address + target.size > size_ ||
          unsignedOverflow_(target.address, target.size)) {
        // Read outside of memory; return an invalid value to signal a fault
        completedReads_.push_back({target, RegisterValue(), request.requestId});
      } else {
        simeng::memory::ReadRespPacket* resp =
            (simeng::memory::ReadRespPacket*)memory_->requestAccess(
                new simeng::memory::ReadPacket{target.address, target.size});
        // Copy the data at the requested memory address into a RegisterValue
        completedReads_.push_back({target,
                                   RegisterValue(resp->data, resp->bytesRead),
                                   request.requestId});
        delete resp;
      }
    }

    // Remove the request from the queue
    pendingRequests_.pop();
  }
}

void FixedLatencyMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                              uint64_t requestId) {
  pendingRequests_.push({target, tickCounter_ + latency_, requestId});
}

void FixedLatencyMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                               const RegisterValue& data) {
  pendingRequests_.push({target, data, tickCounter_ + latency_});
}

const span<MemoryReadResult> FixedLatencyMemoryInterface::getCompletedReads()
    const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FixedLatencyMemoryInterface::clearCompletedReads() {
  completedReads_.clear();
}

bool FixedLatencyMemoryInterface::hasPendingRequests() const {
  return !pendingRequests_.empty();
}

}  // namespace simeng
