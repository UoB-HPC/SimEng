#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(
    std::shared_ptr<memory::MMU> mmu, uint16_t latency, size_t memSize) {
  mmu_ = mmu;
  latency_ = latency;
  size_ = memSize;
}

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
      auto fn = [&](memory::DataPacket* dpkt = NULL) -> void {
        if (dpkt == NULL) return;
        delete dpkt;
      };

      const char* wdata = request.data.getAsVector<char>();
      mmu_->bufferRequest(
          new simeng::memory::WritePacket(target.address, target.size, wdata),
          fn);
    } else {
      auto fn = [&, this](memory::DataPacket* dpkt = NULL) -> void {
        if (dpkt == NULL) {
          this->completedReads_.push_back({target, RegisterValue(), requestId});
          return;
        }
        memory::ReadRespPacket* resp = (memory::ReadRespPacket*)dpkt;
        this->completedReads_.push_back(
            {target, RegisterValue(resp->data, resp->bytesRead), requestId});
        delete resp;
      };

      mmu_->bufferRequest(new memory::ReadPacket(target.address, target.size),
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
