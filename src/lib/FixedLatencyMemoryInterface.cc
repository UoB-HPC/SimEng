#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>
#include <memory>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(
    std::shared_ptr<memory::MMU> mmu, uint16_t latency)
    : mmu_(mmu), latency_(latency) {}

void FixedLatencyMemoryInterface::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      break;
    }

    const auto& target = request.target;
    uint64_t requestId = request.requestId;

    if (request.write) {
      const char* wdata = request.data.getAsVector<char>();
      std::vector<char> dt(wdata, wdata + target.size);
      // Responses to write requests are ignored by passing in a nullptr
      // callback because they don't contain any information relevant to the
      // simulation.
      mmu_->bufferRequest(std::unique_ptr<memory::MemPacket>(
                              memory::MemPacket::createWriteRequest(
                                  target.address, target.size, requestId, dt)),
                          nullptr);
    } else {
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
      mmu_->bufferRequest(std::unique_ptr<memory::MemPacket>(
                              memory::MemPacket::createReadRequest(
                                  target.address, target.size, requestId)),
                          fn);
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
