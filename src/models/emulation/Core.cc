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
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_) {
  // Query and apply initial state
  auto state = isa.getInitialState(processMemory);
  applyStateChange(state);
}

void Core::tick() {
  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
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
  exceptionHandler_ =
      isa_.handleException(instruction, architecturalRegisterFileSet_, memory_);
  processExceptionHandler();
}

void Core::processExceptionHandler() {
  assert(exceptionHandler_ != nullptr &&
         "Attempted to process an exception handler that wasn't present");

  bool success = exceptionHandler_->tick();

  if (!success) {
    // Handler needs further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    pc_ = programByteLength_;
    hasHalted_ = true;
    std::cout << "Halting due to fatal exception" << std::endl;
  } else {
    pc_ = result.instructionAddress;
    applyStateChange(result.stateChange);
  }

  // Clear the handler
  exceptionHandler_ = nullptr;
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
