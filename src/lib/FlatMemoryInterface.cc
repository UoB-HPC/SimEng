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
  // std::cout << "FLAT READ (" << unsigned(target.size) << " Bytes)";
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

  // std::cout << " = " << std::hex;

  // if (target.size == 1) {
  //   std::cout << unsigned(RegisterValue(ptr, target.size).get<uint8_t>());
  // } else if (target.size == 2) {
  //   std::cout << unsigned(RegisterValue(ptr, target.size).get<uint16_t>());
  // } else if (target.size == 4) {
  //   std::cout << unsigned(RegisterValue(ptr, target.size).get<uint32_t>());
  // } else if (target.size == 8) {
  //   std::cout << unsigned(RegisterValue(ptr, target.size).get<uint64_t>());
  // } else {
  //   std::cout << "?";
  // }
  // std::cout << std::dec << std::endl;
}

void FlatMemoryInterface::requestWrite(const MemoryAccessTarget& target,
                                       const RegisterValue& data) {
  // Translate address
  Translation translation = translator_.get_mapping(target.address);
  // std::cout << "FLAT WRITE (" << unsigned(target.size) << " Bytes)";
  // if (target.stackAccess) {
  //   std::cout << " to stack";
  // }
  // std::cout << ": 0x" << std::hex << target.address << std::dec << " -> 0x"
  //           << std::hex << translation.address << std::dec << ":"
  //           << translation.allocation << std::endl;

  assert(translation.address + target.size <= size_ &&
         "Attempted to write beyond memory limit");

  assert(translation.allocation && "Attempted to write to unmapped region");

  auto ptr = memory_ + translation.address;
  // Copy the data from the RegisterValue to memory
  memcpy(ptr, data.getAsVector<char>(), target.size);
}

const span<MemoryReadResult> FlatMemoryInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReads_.data()),
          completedReads_.size()};
}

void FlatMemoryInterface::clearCompletedReads() { completedReads_.clear(); }

bool FlatMemoryInterface::hasPendingRequests() const { return false; }

void FlatMemoryInterface::tick() {}

}  // namespace simeng
