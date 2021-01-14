#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(char* memory,
                                                         size_t size,
                                                         uint16_t latency)
    : memory_(memory), size_(size), latency_(latency) {}

void FixedLatencyMemoryInterface::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      // Stalled.fixedLatencyMemoryUnready
      probeTrace newProbe = {10, trace_cycle, 0};
      Trace* newTrace = new Trace;
      newTrace->setProbeTraces(newProbe);
      probeList.push_back(newTrace);
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
      if (target.address + target.size > size_ ||
          unsignedOverflow_(target.address, target.size)) {
        // Read outside of memory; return an invalid value to signal a fault
        // Exception.fixedLatencyMemoryRead
        probeTrace newProbe = {21, trace_cycle, 0};
        Trace* newTrace = new Trace;
        newTrace->setProbeTraces(newProbe);
        probeList.push_back(newTrace);
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
