#include "Core.hh"

#include <cstring>
#include <iostream>

namespace simeng {
namespace models {
namespace emulation {

Core::Core(const span<char> processMemory, uint64_t entryPoint,
           const Architecture& isa)
    : memory_(processMemory.data()),
      insnPtr_(processMemory.data()),
      programByteLength_(processMemory.size()),
      isa_(isa),
      pc_(entryPoint),
      registerFileSet_(isa.getRegisterFileStructures()) {}

void Core::tick() {
  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  // Fetch
  auto bytesRead = isa_.predecode(insnPtr_ + pc_, 4, pc_, {false, 0}, macroOp_);

  pc_ += bytesRead;

  // Decode
  auto& uop = macroOp_[0];
  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  // Issue
  auto registers = uop->getOperandRegisters();
  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(reg, registerFileSet_.get(reg));
    }
  }

  // Execute
  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    for (auto const& request : addresses) {
      // Copy the data at the requested memory address into a RegisterValue
      auto data =
          simeng::RegisterValue(memory_ + request.first, request.second);

      uop->supplyData(request.first, data);
    }
  } else if (uop->isStore()) {
    uop->generateAddresses();
  }

  uop->execute();

  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  if (uop->isStore()) {
    auto addresses = uop->getGeneratedAddresses();
    auto data = uop->getData();
    for (size_t i = 0; i < addresses.size(); i++) {
      auto request = addresses[i];

      // Copy data to memory
      auto address = memory_ + request.first;
      memcpy(address, data[i].getAsVector<char>(), request.second);
    }
  } else if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();
  }

  // Writeback
  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  for (size_t i = 0; i < results.size(); i++) {
    auto reg = destinations[i];
    registerFileSet_.set(reg, results[i]);
  }
}

void Core::handleException(const std::shared_ptr<Instruction>& instruction) {
  pc_ = programByteLength_;
  hasHalted_ = true;
  isa_.handleException(instruction);

  std::cout << "Halting due to fatal exception" << std::endl;
}

bool Core::hasHalted() const { return hasHalted_; }

std::map<std::string, std::string> Core::getStats() const { return {}; };

}  // namespace emulation
}  // namespace models
}  // namespace simeng
