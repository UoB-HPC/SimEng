#include "simeng/models/emulation/Core.hh"

#include <cstring>
#include <iostream>

namespace simeng {
namespace models {
namespace emulation {

// TODO: Expose as config option
/** The number of bytes fetched each cycle. */
const uint8_t FETCH_SIZE = 4;
const unsigned int clockFrequency = 2.5 * 1e9;

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           uint64_t entryPoint, uint64_t programByteLength,
           const arch::Architecture& isa)
    : instructionMemory_(instructionMemory),
      dataMemory_(dataMemory),
      programByteLength_(programByteLength),
      isa_(isa),
      pc_(entryPoint),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_) {
  // Pre-load the first instruction
  instructionMemory_.requestRead({pc_, FETCH_SIZE});

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
}

void Core::tick() {
  ticks_++;

  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  if (pendingReads_ > 0) {
    // Handle pending reads to a uop
    auto& uop = macroOp_[0];

    const auto& completedReads = dataMemory_.getCompletedReads();
    for (const auto& response : completedReads) {
      assert(pendingReads_ > 0);
      uop->supplyData(response.target.address, response.data);
      pendingReads_--;
    }
    dataMemory_.clearCompletedReads();

    if (pendingReads_ == 0) {
      // Load complete: resume execution
      execute(uop);
    }

    // More data pending, end cycle early
    return;
  }

  // Fetch

  // Find fetched memory that matches the current PC
  const auto& fetched = instructionMemory_.getCompletedReads();
  size_t fetchIndex;
  for (fetchIndex = 0; fetchIndex < fetched.size(); fetchIndex++) {
    if (fetched[fetchIndex].target.address == pc_) {
      break;
    }
  }
  if (fetchIndex == fetched.size()) {
    // Need to wait for fetched instructions
    return;
  }

  const auto& instructionBytes = fetched[fetchIndex].data;
  auto bytesRead = isa_.predecode(instructionBytes.getAsVector<char>(),
                                  FETCH_SIZE, pc_, {false, 0}, macroOp_);

  // Clear the fetched data
  instructionMemory_.clearCompletedReads();

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
      uop->supplyOperand(i, registerFileSet_.get(reg));
    }
  }

  // Execute
  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    if (addresses.size() > 0) {
      // Memory reads are required; request them, set `pendingReads_`
      // accordingly, and end the cycle early
      for (auto const& target : addresses) {
        dataMemory_.requestRead(target);
      }
      pendingReads_ = addresses.size();
      return;
    }
  } else if (uop->isStore()) {
    uop->generateAddresses();
  }

  execute(uop);
}

void Core::execute(std::shared_ptr<Instruction>& uop) {
  uop->execute();

  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  if (uop->isStore()) {
    auto addresses = uop->getGeneratedAddresses();
    auto data = uop->getData();
    for (size_t i = 0; i < addresses.size(); i++) {
      dataMemory_.requestWrite(addresses[i], data[i]);
    }
  } else if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();
    branchesExecuted_++;
  }

  // Writeback
  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  for (size_t i = 0; i < results.size(); i++) {
    auto reg = destinations[i];
    registerFileSet_.set(reg, results[i]);
  }

  instructionsExecuted_++;

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
}

void Core::handleException(std::shared_ptr<Instruction>& instruction) {
  exceptionHandler_ = isa_.handleException(instruction, *this, dataMemory_);
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

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
}

void Core::applyStateChange(const arch::ProcessStateChange& change) {
  // Update registers
  for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
    registerFileSet_.set(change.modifiedRegisters[i],
                         change.modifiedRegisterValues[i]);
  }

  // Update memory
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    dataMemory_.requestWrite(change.memoryAddresses[i],
                             change.memoryAddressValues[i]);
  }
}

bool Core::hasHalted() const { return hasHalted_; }

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return instructionsExecuted_;
}

uint64_t Core::getSystemTimer() const {
  return ticks_ / (clockFrequency / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  return {{"instructions", std::to_string(instructionsExecuted_)},
          {"branch.executed", std::to_string(branchesExecuted_)}};
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
