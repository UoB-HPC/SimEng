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
      registerFileSet_(isa.getRegisterFileStructures()) {
  // Query and apply initial state
  std::cout << "Process memory size: " << std::hex << processMemory.size()
            << std::dec << std::endl;
  auto state = isa.getInitialState(processMemory);
  applyStateChange(state);
}

void Core::tick() {
  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  // std::cout << "0x" << std::hex << pc_ << std::dec << std::endl;

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
      uop->supplyData(request.first, readMemory(request));
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
      writeMemory(addresses[i], data[i]);
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
  auto result = isa_.handleException(instruction, registerFileSet_, memory_);

  if (result.fatal) {
    pc_ = programByteLength_;
    hasHalted_ = true;
    std::cout << "Halting due to fatal exception" << std::endl;
    return;
  }

  pc_ = result.instructionAddress;
  applyStateChange(result.stateChange);
}

void Core::applyStateChange(const ProcessStateChange& change) {
  // Update registers
  for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
    registerFileSet_.set(change.modifiedRegisters[i],
                         change.modifiedRegisterValues[i]);
  }

  // Update memory
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    writeMemory(change.memoryAddresses[i], change.memoryAddressValues[i]);
  }
}

RegisterValue Core::readMemory(
    const std::pair<uint64_t, uint8_t>& request) const {
  assert(request.first + request.second <= programByteLength_ &&
         "Attempted to load from outside memory limit");

  // Copy the data at the requested memory address into a RegisterValue
  const char* address = memory_ + request.first;
  return simeng::RegisterValue(address, request.second);
}

void Core::writeMemory(const std::pair<uint64_t, uint8_t>& request,
                       const RegisterValue& data) {
  auto address = memory_ + request.first;
  assert(request.first + request.second <= programByteLength_ &&
         "Attempted to store outside memory limit");
  memcpy(address, data.getAsVector<char>(), request.second);
}

bool Core::hasHalted() const { return hasHalted_; }

std::map<std::string, std::string> Core::getStats() const { return {}; };

}  // namespace emulation
}  // namespace models
}  // namespace simeng
