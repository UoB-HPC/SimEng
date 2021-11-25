#include "simeng/FixedLatencyMemoryInterface.hh"

#include <cassert>
#include <iostream>

namespace simeng {

FixedLatencyMemoryInterface::FixedLatencyMemoryInterface(char* memory,
                                                         size_t size,
                                                         uint16_t latency,
                                                         Translator& translator)
    : memory_(memory),
      size_(size),
      latency_(latency),
      translator_(translator) {}

void FixedLatencyMemoryInterface::tick() {
  tickCounter_++;

  while (pendingRequests_.size() > 0) {
    const auto& request = pendingRequests_.front();

    if (request.readyAt > tickCounter_) {
      // Head of queue isn't ready yet; end cycle
      break;
    }

    const auto& target = request.target;
    Translation translation = translator_.get_mapping(target.address);

    if (request.write) {
      // std::cout << "FIXED WRITE (" << unsigned(target.size) << " Bytes)";
      // if (target.stackAccess) {
      //   std::cout << " to stack";
      // }
      // std::cout << ": 0x" << std::hex << target.address << std::dec << " ->
      // 0x"
      //           << std::hex << translation.address << std::dec << ":"
      //           << translation.allocation << std::endl;
      // Write: write data directly to memory
      assert(translation.address + target.size <= size_ &&
             "Attempted to write beyond memory limit");

      assert(translation.allocation && "Attempted to write to unmapped region");

      auto ptr = memory_ + translation.address;
      // Copy the data from the RegisterValue to memory
      memcpy(ptr, request.data.getAsVector<char>(), target.size);
    } else {
      // std::cout << "FIXED READ (" << unsigned(target.size) << " Bytes)";
      // if (target.stackAccess) {
      //   std::cout << " from stack";
      // }
      // std::cout << ": 0x" << std::hex << target.address << std::dec << " ->
      // 0x"
      //           << std::hex << translation.address << std::dec << ":"
      //           << translation.allocation;
      // Read: read data into `completedReads`
      if (!translation.allocation ||
          (translation.address + target.size > size_)) {
        // Read outside of memory; return an invalid value to signal a fault
        completedReads_.push_back({target, RegisterValue(), request.requestId});
      } else {
        const char* ptr = memory_ + translation.address;

        // Copy the data at the requested memory address into a RegisterValue
        completedReads_.push_back(
            {target, RegisterValue(ptr, target.size), request.requestId});

        //   std::cout << " = " << std::hex;

        //   if (target.size == 1) {
        //     std::cout << unsigned(RegisterValue(ptr,
        //     target.size).get<uint8_t>());
        //   } else if (target.size == 2) {
        //     std::cout << unsigned(
        //         RegisterValue(ptr, target.size).get<uint16_t>());
        //   } else if (target.size == 4) {
        //     std::cout << unsigned(
        //         RegisterValue(ptr, target.size).get<uint32_t>());
        //   } else if (target.size == 8) {
        //     std::cout << unsigned(
        //         RegisterValue(ptr, target.size).get<uint64_t>());
        //   } else {
        //     std::cout << "?";
        //   }
      }
      // std::cout << std::dec << std::endl;
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
