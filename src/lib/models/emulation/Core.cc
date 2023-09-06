#include "simeng/models/emulation/Core.hh"

#include <cstring>

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
      architecturalRegisterFileSet_(registerFileSet_),
      interruptId_(-1) {
  // Pre-load the first instruction
  instructionMemory_.requestRead({pc_, FETCH_SIZE});

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
}

void Core::tick() {
  ticks_++;

  if (hasHalted_) return;

  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  // Fetch

  // Determine if new uops are needed to be fetched
  if (!microOps_.size()) {
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
                                    FETCH_SIZE, pc_, macroOp_);

    // Clear the fetched data
    instructionMemory_.clearCompletedReads();

    pc_ += bytesRead;

    // Decode
    for (size_t index = 0; index < macroOp_.size(); index++) {
      microOps_.push(std::move(macroOp_[index]));
    }
  }

  auto& uop = microOps_.front();

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
    previousAddresses_.clear();
    if (uop->exceptionEncountered()) {
      handleException(uop);
      return;
    }
    if (addresses.size() > 0) {
      // Memory reads are required; request them, set `pendingReads_`
      // accordingly, and end the cycle early
      for (auto const& target : addresses) {
        dataMemory_.requestRead(target);
        // Store addresses for use by next store data operation
        previousAddresses_.push_back(target);
      }
      pendingReads_ = addresses.size();
      const auto& completedReads = dataMemory_.getCompletedReads();
      for (const auto& response : completedReads) {
        assert(pendingReads_ > 0);
        uop->supplyData(response.target.address, response.data);
        pendingReads_--;
      }
      dataMemory_.clearCompletedReads();
    } else {
      // Early execution due to lacking addresses
      execute(uop);
      return;
    }
  } else if (uop->isStoreAddress()) {
    auto addresses = uop->generateAddresses();
    previousAddresses_.clear();
    if (uop->exceptionEncountered()) {
      handleException(uop);
      return;
    }
    // Store addresses for use by next store data operation
    for (auto const& target : addresses) {
      previousAddresses_.push_back(target);
    }
    if (uop->isStoreData()) {
      execute(uop);
    } else {
      // Fetch memory for next cycle
      instructionMemory_.requestRead({pc_, FETCH_SIZE});
      microOps_.pop();
    }

    return;
  }

  execute(uop);

  interruptId_ = isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);
}

void Core::execute(std::shared_ptr<Instruction>& uop) {
  if (interruptId_ >= 0)
    uop->raiseInterrupt(interruptId_);
  else
    uop->execute();

  if (uop->exceptionEncountered()) {
    instructionsExecuted_++;
    isa_.updateInstrTrace(uop, &registerFileSet_,
                          ticks_);  // Handle ECALL into trace here
    handleException(uop);
    return;
  }

  if (uop->isStoreData()) {
    auto results = uop->getResults();
    auto destinations = uop->getDestinationRegisters();
    auto data = uop->getData();
    for (size_t i = 0; i < previousAddresses_.size(); i++) {
      dataMemory_.requestWrite(previousAddresses_[i], data[i]);
    }
  } else if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();
    branchesExecuted_++;
  }

  // Writeback
  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  if (uop->isStoreData()) {
    for (size_t i = 0; i < results.size(); i++) {
      auto reg = destinations[i];
      registerFileSet_.set(reg, results[i]);
    }
  } else {
    for (size_t i = 0; i < results.size(); i++) {
      auto reg = destinations[i];
      registerFileSet_.set(reg, results[i]);
    }
  }

  if (uop->isLastMicroOp()) {
    instructionsExecuted_++;
    // TODO: This is architecture-specific. It's here for the reference and
    // should(will) be refactored later
    uint16_t sysreg_instrret =
        isa_.getSystemRegisterTag(arch::riscv::riscv_sysreg::SYSREG_INSTRRET);
    uint16_t sysreg_cycle =
        isa_.getSystemRegisterTag(arch::riscv::riscv_sysreg::SYSREG_CYCLE);
    // NOTE: 64-bit system registers are not implemented yet
    // TODO: Maybe make use of byteLength and remove is32BitMode() function?
    if (isa_.is32BitMode()) {
      registerFileSet_.set(Register{0x2, sysreg_instrret},
                           RegisterValue(instructionsExecuted_, 4));
      registerFileSet_.set(Register{0x2, sysreg_cycle},
                           RegisterValue(ticks_, 4));
    }
    isa_.updateInstrTrace(uop, &registerFileSet_, ticks_);
  }

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
  microOps_.pop();
}

void Core::handleException(const std::shared_ptr<Instruction>& instruction) {
  exceptionHandler_ = isa_.handleException(instruction, *this, dataMemory_);
  processExceptionHandler();
}

void Core::processExceptionHandler() {
  assert(exceptionHandler_ != nullptr &&
         "Attempted to process an exception handler that wasn't present");
  if (dataMemory_.hasPendingRequests()) {
    // Must wait for all memory requests to complete before processing the
    // exception
    return;
  }

  bool success = exceptionHandler_->tick();
  if (!success) {
    // Handler needs further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    pc_ = programByteLength_;
    hasHalted_ = true;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    pc_ = result.instructionAddress;
    applyStateChange(result.stateChange);
  }

  // Clear the handler
  exceptionHandler_ = nullptr;

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
  microOps_.pop();
}

void Core::applyStateChange(const arch::ProcessStateChange& change) {
  // Update registers in accoradance with the ProcessStateChange type
  switch (change.type) {
    case arch::ChangeType::INCREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() +
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    case arch::ChangeType::DECREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() -
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    default: {  // arch::ChangeType::REPLACEMENT
      // If type is ChangeType::REPLACEMENT, set new values
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(change.modifiedRegisters[i],
                             change.modifiedRegisterValues[i]);
      }
      break;
    }
  }

  // Update memory
  // TODO: Analyse if ChangeType::INCREMENT or ChangeType::DECREMENT case is
  // required for memory changes
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
