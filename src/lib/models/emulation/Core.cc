#include "simeng/models/emulation/Core.hh"

#include <cstring>

namespace simeng {
namespace models {
namespace emulation {

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           const arch::Architecture& isa, std::shared_ptr<memory::MMU> mmu,
           arch::sendSyscallToHandler handleSyscall)
    : instructionMemory_(instructionMemory),
      dataMemory_(dataMemory),
      mmu_(mmu),
      isa_(isa),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_),
      handleSyscall_(handleSyscall) {
  // Create exception handler based on chosen architecture
  exceptionHandlerFactory(Config::get()["Core"]["ISA"].as<std::string>());
}

void Core::tick() {
  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

  switch (status_) {
    case CoreStatus::idle:
      idle_ticks_++;
      return;
    case CoreStatus::switching:
      // Ensure there are no instructions left to execute and there's no active
      // exception before context switching.
      if (microOps_.empty() && (exceptionGenerated_ == false)) {
        macroOp_.clear();
        pendingReads_ = 0;
        previousAddresses_.clear();
        status_ = CoreStatus::idle;
        return;
      }
      break;
    case CoreStatus::halted:
      return;
    default:
      break;
  }

  // Increase tick count for current process execution
  procTicks_++;

  if (pc_ >= programByteLength_) {
    std::cout << "WOOOOOOOOOOOOOPS" << std::endl;
    std::cout << "TID: " << currentTID_ << "PC VAL: " << pc_
              << " AT TICK: " << ticks_ << std::endl;
    status_ = CoreStatus::idle;
    return;
  }

  if (exceptionGenerated_) {
    processException();
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

  // Determine if new uops are needed to be fetched
  if (microOps_.empty() && (status_ != CoreStatus::switching)) {
    // Fetch
    instructionMemory_.requestRead({pc_, FETCH_SIZE});
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
      microOps_.pop();
    }

    return;
  }

  execute(uop);
}

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

  microOps_.pop();
}

void Core::handleException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionHandler_->registerException(instruction);
  processException();
}

void Core::processException() {
  assert(exceptionGenerated_ != false &&
         "[SimEng:Core] Attempted to process an exception handler that wasn't "
         "active");
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
    status_ = CoreStatus::halted;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    pc_ = result.instructionAddress;
    applyStateChange(result.stateChange);
    if (result.idleAfterSyscall) {
      status_ = CoreStatus::idle;
      contextSwitches_++;
    }
  }

  exceptionGenerated_ = false;

  microOps_.pop();
}

void Core::applyStateChange(const OS::ProcessStateChange& change) {
  // Update registers in accoradance with the ProcessStateChange type
  switch (change.type) {
    case OS::ChangeType::INCREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() +
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    case OS::ChangeType::DECREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() -
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    default: {  // OS::ChangeType::REPLACEMENT
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

CoreStatus Core::getStatus() { return status_; }

void Core::setStatus(CoreStatus newStatus) { status_ = newStatus; }

uint64_t Core::getCurrentTID() const { return currentTID_; }

uint64_t Core::getCoreId() const { return coreId_; }

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

void Core::sendSyscall(OS::SyscallInfo syscallInfo) const {
  handleSyscall_(syscallInfo);
}

void Core::receiveSyscallResult(const OS::SyscallResult result) const {
  exceptionHandler_->processSyscallResult(result);
}

uint64_t Core::getInstructionsRetiredCount() const {
  return instructionsExecuted_;
}

std::map<std::string, std::string> Core::getStats() const {
  return {{"instructions", std::to_string(instructionsExecuted_)},
          {"branch.executed", std::to_string(branchesExecuted_)},
          {"idle.ticks", std::to_string(idle_ticks_)},
          {"context.switches", std::to_string(contextSwitches_)}};
}

void Core::schedule(simeng::OS::cpuContext newContext) {
  currentTID_ = newContext.TID;
  programByteLength_ = newContext.progByteLen;
  pc_ = newContext.pc;
  std::cout << "TID: " << currentTID_ << " PC TO SCHEDULE " << pc_
            << " AT TICK: " << ticks_ << std::endl;
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      registerFileSet_.set({(uint8_t)type, (uint16_t)tag},
                           newContext.regFile[type][tag]);
    }
  }
  status_ = CoreStatus::executing;
  procTicks_ = 0;
  isa_.updateAfterContextSwitch(newContext);
  mmu_->setTid(currentTID_);
}

bool Core::interrupt() {
  if (exceptionGenerated_ == false) {
    status_ = CoreStatus::switching;
    contextSwitches_++;
    return true;
  }
  return false;
}

uint64_t Core::getCurrentProcTicks() const { return procTicks_; }

simeng::OS::cpuContext Core::getCurrentContext() const {
  OS::cpuContext newContext;
  newContext.TID = currentTID_;
  newContext.pc = pc_;
  // progByteLen will not change in process so do not need to set it
  // Don't need to explicitly save SP as will be in reg file contents
  auto regFileStruc = isa_.getRegisterFileStructures();
  newContext.regFile.resize(regFileStruc.size());
  for (size_t i = 0; i < regFileStruc.size(); i++) {
    newContext.regFile[i].resize(regFileStruc[i].quantity);
  }
  // Set all reg Values
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      newContext.regFile[type][tag] =
          registerFileSet_.get({(uint8_t)type, (uint16_t)tag});
    }
  }
  // Do not need to explicitly set newContext.sp as it will be included in
  // regFile
  return newContext;
}

}  // namespace emulation
}  // namespace models
}  // namespace simeng
