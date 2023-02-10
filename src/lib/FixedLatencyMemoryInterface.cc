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
      auto fn = [&](memory::WriteResponse dpkt) -> void {};

      const char* wdata = request.data.getAsVector<char>();
      memory::WriteRequest req{target.address, target.size};

      std::copy(wdata, wdata + target.size, req.data().begin());
      mmu_->bufferRequest(req, fn);
    } else {
      auto fn = [&, this](memory::ReadResponse dpkt) -> void {
        if (dpkt.address_ == ~(uint64_t)0) {
          this->completedReads_.push_back({target, RegisterValue(), requestId});
          return;
        }
        this->completedReads_.push_back(
            {target, RegisterValue(dpkt.data().begin(), dpkt.size_),
             requestId});
      };

      mmu_->bufferRequest(memory::ReadRequest(target.address, target.size), fn);
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
