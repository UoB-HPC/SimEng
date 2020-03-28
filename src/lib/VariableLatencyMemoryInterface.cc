#include "simeng/VariableLatencyMemoryInterface.hh"

#include <cassert>

namespace simeng {

VariableLatencyMemoryInterface::VariableLatencyMemoryInterface(char* memory,
                                                               size_t size,
                                                               uint16_t iLatency,
                                                               uint16_t fpLatency)
    : memory_(memory), size_(size), iLatency_(iLatency), fpLatency_(fpLatency) {}

void VariableLatencyMemoryInterface::tick() {
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
      assert(target.address + target.size <= size_ &&
             "Attempted to write beyond memory limit");

      auto ptr = memory_ + target.address;
      // Copy the data from the RegisterValue to memory
      memcpy(ptr, request.data.getAsVector<char>(), target.size);
    } else {
      // Read: read data into `completedReads`
      if (target.address + target.size > size_) {
        // Read outside of memory; return an invalid value to signal a fault
        completedReads_.push_back({target, RegisterValue(), request.requestId});
      } else {
        const char* ptr = memory_ + target.address;

        // Copy the data at the requested memory address into a RegisterValue
        completedReads_.push_back(
            {target, RegisterValue(ptr, target.size), request.requestId});
      }
    }

    // Remove the request from the queue
    pendingRequests_.pop();
  }
}

void VariableLatencyMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                                 uint64_t requestId) {
  uint16_t latency = iLatency_;
  if (target.isFP) latency = fpLatency_;
  pendingRequests_.push({target, tickCounter_ + latency, requestId});
}

void VariableLatencyMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                                 const RegisterValue& data) {
  uint16_t latency = iLatency_;
  if (target.isFP) latency = fpLatency_;
  pendingRequests_.push({target, data, tickCounter_ + latency});
}

const span<MemoryReadResult> VariableLatencyMemoryInterface::getCompletedReads()
    const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void VariableLatencyMemoryInterface::clearCompletedReads() {
  completedReads_.clear();
}

bool VariableLatencyMemoryInterface::hasPendingRequests() const {
  return !pendingRequests_.empty();
}

}  // namespace simeng
