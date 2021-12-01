#include "simeng/FlatMemoryInterface.hh"

#include <cassert>
#include <iostream>

namespace simeng {

FlatMemoryInterface::FlatMemoryInterface(char* memory, size_t size,
                                         Translator& translator)
    : memory_(memory), size_(size), translator_(translator) {}

void FlatMemoryInterface::requestRead(const MemoryAccessTarget& target,
                                      uint64_t requestId) {
  // Translate address
  Translation translation = translator_.get_mapping(target.address);
  // std::cout << "\tFLAT READ (" << unsigned(target.size) << " Bytes)";
  // if (target.stackAccess) {
  //   std::cout << " from stack";
  // }
  // std::cout << ": 0x" << std::hex << target.address << std::dec << " -> 0x"
  //           << std::hex << translation.address << std::dec << ":"
  //           << translation.allocation;
  if (!translation.allocation || (translation.address + target.size > size_)) {
    // Read outside of memory; return an invalid value to signal a fault
    completedReads_.push_back({target, RegisterValue(), requestId});
    // std::cout << std::dec << std::endl;
    return;
  }

  const char* ptr = memory_ + translation.address;

  // Copy the data at the requested memory address into a RegisterValue
  completedReads_.push_back(
      {target, RegisterValue(ptr, target.size), requestId});

  // if (target.size == 1) {
  //   std::cout << " = 0x" << std::hex << unsigned(*(uint8_t*)ptr) << std::dec;
  // } else if (target.size == 2) {
  //   std::cout << " = 0x" << std::hex << *(uint16_t*)ptr << std::dec;
  // } else if (target.size == 4) {
  //   std::cout << " = 0x" << std::hex << *(uint32_t*)ptr << std::dec;
  // } else if (target.size == 8) {
  //   std::cout << " = 0x" << std::hex << *(uint64_t*)ptr << std::dec;
  // } else {
  //   std::cout << "?";
  // }
  // std::cout << std::endl;
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  // Translate address
  Translation translation = translator_.get_mapping(target.address);
  // std::cout << "\tFLAT WRITE (" << unsigned(target.size) << " Bytes)";
  // if (target.stackAccess) {
  //   std::cout << " to stack";
  // }
  // std::cout << ": 0x" << std::hex << target.address << std::dec << " -> 0x"
  //           << std::hex << translation.address << std::dec << ":"
  //           << translation.allocation << " -> ";
  // if (translation.address + target.size > size_) {
  //   std::cout << std::dec << std::endl;
  //   return;
  // }
  assert(translation.address + target.size <= size_ &&
         "Attempted to write beyond memory limit");

  assert(translation.allocation && "Attempted to write to unmapped region");

  auto ptr = memory_ + translation.address;
  // Copy the data from the RegisterValue to memory
  memcpy(ptr, data.getAsVector<char>(), target.size);
  // std::cout << "written" << std::endl;
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
