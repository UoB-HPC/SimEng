#include "simeng/models/emulation/Core.hh"

#include <cstring>

namespace simeng {
namespace models {
namespace emulation {

/** The number of bytes fetched each cycle. */
const uint8_t FETCH_SIZE = 4;

Core::Core(memory::MemoryInterface& instructionMemory,
           memory::MemoryInterface& dataMemory, uint64_t entryPoint,
           uint64_t programByteLength, const arch::Architecture& isa)
    : simeng::Core(dataMemory, isa, config::SimInfo::getArchRegStruct()),
      instructionMemory_(instructionMemory),
      architecturalRegisterFileSet_(registerFileSet_),
      pc_(entryPoint),
      programByteLength_(programByteLength) {
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

  if (pendingReads_ > 0) {
    // Handle pending reads to a uop
    auto& uop = microOps_.front();

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
  auto registers = uop->getSourceRegisters();
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
      return;
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
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);
}

bool Core::hasHalted() const { return hasHalted_; }

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return instructionsExecuted_;
}

std::map<std::string, std::string> Core::getStats() const {
  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(instructionsExecuted_)},
          {"branch.executed", std::to_string(branchesExecuted_)}};
};

void Core::execute(std::shared_ptr<Instruction>& uop) {
  uop->execute();

  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  if (uop->isStoreData()) {
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

  if (uop->isLastMicroOp()) instructionsExecuted_++;

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

}  // namespace emulation
}  // namespace models
}  // namespace simeng
