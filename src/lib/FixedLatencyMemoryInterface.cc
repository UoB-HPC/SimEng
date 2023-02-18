#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(
    std::shared_ptr<memory::MMU> mmu, uint16_t latency, size_t memSize)
    : mmu_(mmu), latency_(latency), size_(memSize) {}

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
      std::vector<char> dt(target.size, '\0');
      std::copy(wdata, wdata + target.size, dt.data());

      // Responses to write requests are ignored by passing in a nullptr
      // callback because they don't contain any information relevant to the
      // simulation.
      mmu_->bufferRequest(
          memory::DataPacket(target.address, target.size, memory::WRITE_REQUEST,
                             requestId, dt),
          nullptr);
    } else {
      // Instantiate a callback function which will be invoked with the response
      // to a read request.
      auto fn = [&, this](struct memory::DataPacket packet) -> void {
        if (packet.inFault_) {
          this->completedReads_.push_back({target, RegisterValue(), requestId});
          return;
        }
        this->completedReads_.push_back(
            {target, RegisterValue(packet.data_.data(), packet.size_),
             requestId});
      };
      mmu_->bufferRequest(memory::DataPacket(target.address, target.size,
                                             memory::READ_REQUEST, requestId),
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
