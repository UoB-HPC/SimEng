#include "simeng/models/mcu/Core.hh"

#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

#include "simeng/arch/riscv/SystemRegister.hh"

namespace simeng {
namespace models {
namespace mcu {

// TODO: Replace with config options
const unsigned int blockSize = 16;
const unsigned int clockFrequency = 2.5 * 1e9;

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           uint64_t processMemorySize, uint64_t entryPoint,
           const arch::Architecture& isa, BranchPredictor& branchPredictor, YAML::Node config)
    : dataMemory_(dataMemory),
      isa_(isa),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_),
      fetchToDecodeBuffer_(1, {}),
      decodeToExecuteBuffer_(1, nullptr, 1),
      completionSlots_(2, {1, nullptr}),
      regDepMap_(isa.getRegisterFileStructures(), registerFileSet_),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, blockSize, isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToExecuteBuffer_,
                  branchPredictor,
                  [this](auto instruction) { return canIssue(instruction); }),
      writebackUnit_(completionSlots_, registerFileSet_, [](auto insnId) {},
                     [this](auto instruction) {removeDep(instruction);},
                     [this](auto instruction) { return removeInstrOrderQ(instruction); }),
      loadStoreQueue_(4, dataMemory, { completionSlots_.data()+1, 1 }, [this](auto regs, auto values) { forwardOperands(regs, values); }, false, 4, 4, 2, 1, 1),
      executeUnit_(
          decodeToExecuteBuffer_, completionSlots_[0],
          [this](auto regs, auto values) { forwardOperands(regs, values); },
          [this](auto instruction) { loadStoreQueue_.addLoad(instruction); },
          [this](auto instruction) { loadStoreQueue_.addStore(instruction); },
          [this](auto instruction) { raiseException(instruction); },
          [this](auto instruction) { addInstrOrderQ(instruction); },
          [this]() { return isInterruptPending(); },
          branchPredictor, false),
      interruptId_(-1) {
  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);

  maxStallCycleTimeout = -1;
  maxSimCycleTimeout = -1;
  maxInstrTimeout = -1;
  if(config["Core"]["EnableHaltCheck"].IsDefined() && config["Core"]["EnableHaltCheck"].as<bool>()) {
    enableHaltCheck = true;
    if(config["Core"]["MaxStallCycleTimeout"].IsDefined()) {
      maxStallCycleTimeout = config["Core"]["MaxStallCycleTimeout"].as<uint64_t>();
    }
    if(config["Core"]["MaxSimCycleTimeout"].IsDefined()) {
      maxSimCycleTimeout = config["Core"]["MaxSimCycleTimeout"].as<uint64_t>();
    }
    if(config["Core"]["MaxInstrTimeout"].IsDefined()) {
      maxInstrTimeout = config["Core"]["MaxInstrTimeout"].as<uint64_t>();
    }
  }
};

void Core::checkHalting() {
  if(!enableHaltCheck) return;

  if (((ticks_ - lastCommitTick_) > maxStallCycleTimeout)) {
    std::cout << std::dec << "[SimEng:Core] Max Pipeline stall cycle timeout reached at tick: " <<  (ticks_ - lastCommitTick_) << std::endl;
    hasHalted_ = true;
  }

  if((ticks_ > maxSimCycleTimeout)) {
    std::cout << std::dec << "[SimEng:Core] Max Simulation cycle timeout reached at tick: " <<  ticks_ << std::endl;
    hasHalted_ = true;    
  }

  if((getInstructionsRetiredCount() > maxInstrTimeout)) {
    std::cout << std::dec << "[SimEng:Core] Max Instruction count timeout reached at tick: " <<  ticks_ << std::endl;
    hasHalted_ = true;
  }
}

void Core::tick() {
  ticks_++;

  checkHalting();

  if (hasHalted_) return;

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  // writebackUnit_.tick();
  // for(std::shared_ptr<Instruction> inst: writebackUnit_.getInstsForTrace()) {
  //   uint16_t sysreg_instrret = isa_.getSystemRegisterTag(arch::riscv32::riscv_sysreg::SYSREG_INSTRRET);
  //   uint16_t sysreg_cycle = isa_.getSystemRegisterTag(arch::riscv32::riscv_sysreg::SYSREG_CYCLE);
  //   registerFileSet_.set(Register{0x2, sysreg_instrret}, RegisterValue(static_cast<uint32_t>(writebackUnit_.getInstructionsWrittenCount()), 4));
  //   registerFileSet_.set(Register{0x2, sysreg_cycle}, RegisterValue(static_cast<uint32_t>(ticks_), 4));
  //   isa_.updateInstrTrace(inst, &registerFileSet_, ticks_);
  //   if(inst->isLoad()) {
  //     loadStoreQueue_.commitLoad(inst);
  //   } else if(inst->isStoreData()) {
  //     loadStoreQueue_.commitStore(inst);
  //   }
  //   lastCommitTick_ = ticks_;
  // }
  // writebackUnit_.traceFinished();


  loadStoreQueue_.processResponse();
  completionSlots_[1].tick();

  // Tick units
  fetchUnit_.tick();
  decodeUnit_.tick();
  executeUnit_.tick();

  // Wipe any data read responses, as they will have been handled by this point
  //dataMemory_.clearCompletedReads();

  loadStoreQueue_.tick();
  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();
  for(std::shared_ptr<Instruction> inst: writebackUnit_.getInstsForTrace()) {
    uint16_t sysreg_instrret = isa_.getSystemRegisterTag(arch::riscv::riscv_sysreg::SYSREG_INSTRRET);
    uint16_t sysreg_cycle = isa_.getSystemRegisterTag(arch::riscv::riscv_sysreg::SYSREG_CYCLE);
    registerFileSet_.set(Register{0x2, sysreg_instrret}, RegisterValue(static_cast<uint32_t>(writebackUnit_.getInstructionsWrittenCount()), 4));
    registerFileSet_.set(Register{0x2, sysreg_cycle}, RegisterValue(static_cast<uint32_t>(ticks_), 4));
    isa_.updateInstrTrace(inst, &registerFileSet_, ticks_);
    if(inst->isLoad()) {
      loadStoreQueue_.commitLoad(inst);
    } else if(inst->isStoreData()) {
      loadStoreQueue_.commitStore(inst);
    }
    lastCommitTick_ = ticks_;
  }
  // writebackUnit_.traceFinished();
  // Read pending registers for ready-to-execute uop; must happen after execute
  // to allow operand forwarding to take place first
  // readRegisters();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer_.tick();
  decodeToExecuteBuffer_.tick();
  completionSlots_[0].tick();
  // for (auto& buffer : completionSlots_) {
  //   buffer.tick();
  // }

  // if (exceptionGenerated_) {
  //   handleException();
  //   //fetchUnit_.requestFromPC();
  //   return;
  // }

  // Check for flush
  if (executeUnit_.shouldFlush()) {
    // Flush was requested at execute stage
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Execute)
    auto targetAddress = executeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchUnit_.flushPredictor(targetAddress);
    // Ensure instructions in the buffer if any are set to be flushed before being removed, this helps with removing the respective dependencies if any
    decodeUnit_.purgeFlushed();
    executeUnit_.purgeFlushed();
    fetchToDecodeBuffer_.fill({});
    decodeToExecuteBuffer_.fill(nullptr);
    loadStoreQueue_.purgeFlushed();
    regDepMap_.purgeFlushed();

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    assert(false && "Decode unit should not generate flush");
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

    flushes_++;
  }

  if (exceptionGenerated_) {
    handleException();
    //fetchUnit_.requestFromPC();
    return;
  }

  fetchUnit_.requestFromPC();
  interruptId_ = isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);
}

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, there
  // are no uops at the head of any buffer, and no exception is currently being
  // handled.
  bool decodePending = fetchToDecodeBuffer_.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer_.getHeadSlots()[0] != nullptr;
  bool writebackPending = completionSlots_[0].getHeadSlots()[0] != nullptr;
  writebackPending |= completionSlots_[1].getHeadSlots()[0] != nullptr;

  return (fetchUnit_.hasHalted() && !decodePending && !writebackPending &&
          !executePending && exceptionHandler_ == nullptr);
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return writebackUnit_.getInstructionsWrittenCount();
}

uint64_t Core::getSystemTimer() const {
  // TODO: This will need to be changed if we start supporting DVFS.
  return ticks_ / (clockFrequency / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit_.getInstructionsWrittenCount();
  auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  // Sum up the branch stats reported across the execution units.
  uint64_t totalBranchesExecuted = 0;
  uint64_t totalBranchMispredicts = 0;
  totalBranchesExecuted += executeUnit_.getBranchExecutedCount();
  totalBranchMispredicts += executeUnit_.getBranchMispredictedCount();
  auto branchMissRate = 100.0f * static_cast<float>(totalBranchMispredicts) /
                        static_cast<float>(totalBranchesExecuted);
  std::ostringstream branchMissRateStr;
  branchMissRateStr << std::setprecision(3) << branchMissRate << "%";

  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(retired)},
          {"ipc", ipcStr.str()},
          {"flushes", std::to_string(flushes_)},
          {"branch.executed", std::to_string(totalBranchesExecuted)},
          {"branch.mispredict", std::to_string(totalBranchMispredicts)},
          {"branch.missrate", branchMissRateStr.str()},
          {"lsu.ldminlatency", std::to_string(loadStoreQueue_.getMinLdLat())},
          {"lsu.ldmaxlatency", std::to_string(loadStoreQueue_.getMaxLdLat())},
          {"lsu.ldavglatency", std::to_string(loadStoreQueue_.getAvgLdLat())}};
}

void Core::raiseException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  exceptionGenerated_ = false;

  exceptionHandler_ =
      isa_.handleException(exceptionGeneratingInstruction_, *this, dataMemory_);

  processExceptionHandler();
//  isa_.updateInstrTrace(exceptionGeneratingInstruction_, &registerFileSet_, ticks_);
//  lastCommitTick_ = ticks_;
//  assert(removeInstrOrderQ(exceptionGeneratingInstruction_) && "Unexpected instruction at the top of inorder instr queue on exception");

  //TODO: This is not a good point to flush the pipeline if the exception is not changing the PC.

  // Flush pipeline
//  decodeUnit_.purgeFlushed();
//  executeUnit_.purgeFlushed();
//  fetchToDecodeBuffer_.fill({});
//  decodeToExecuteBuffer_.fill(nullptr);
//  loadStoreQueue_.purgeFlushed();
//  completionSlots_[0].fill(nullptr);
//  completionSlots_[1].fill(nullptr);
//  regDepMap_.purgeFlushed();
}

void Core::processExceptionHandler() {
  assert(exceptionHandler_ != nullptr &&
         "Attempted to process an exception handler that wasn't present");
  if (dataMemory_.hasPendingRequests()) {
    // Must wait for all memory requests to complete before processing the
    // exception
    return;
  }

  auto success = exceptionHandler_->tick();
  if (!success) {
    // Exception handler requires further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    hasHalted_ = true;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    //fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
  }

  exceptionHandler_ = nullptr;
}

void Core::loadData(const std::shared_ptr<Instruction>& instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  for (const auto& target : addresses) {
    dataMemory_.requestRead(target);
  }

  // NOTE: This model only supports zero-cycle data memory models, and will not
  // work unless data requests are handled synchronously.
  for (const auto& response : dataMemory_.getCompletedReads()) {
    instruction->supplyData(response.target.address, response.data);
  }

  assert(instruction->hasAllData() &&
         "Load instruction failed to obtain all data this cycle");

  instruction->execute();

  if (instruction->isStoreData()) {
    storeData(instruction);
  }
}

void Core::storeData(const std::shared_ptr<Instruction>& instruction) {
  if (instruction->isStoreAddress()) {
    auto addresses = instruction->getGeneratedAddresses();
    for (auto const& target : addresses) {
      previousAddresses_.push(target);
    }
  }
  if (instruction->isStoreData()) {
    const auto data = instruction->getData();
    for (size_t i = 0; i < data.size(); i++) {
      dataMemory_.requestWrite(previousAddresses_.front(), data[i]);
      previousAddresses_.pop();
    }
  }
}

void Core::forwardOperands(const span<Register>& registers,
                           const span<RegisterValue>& values) {
  return;
  // assert(registers.size() == values.size() &&
  //        "Mismatched register and value vector sizes");

  // const auto& uop = decodeToExecuteBuffer_.getTailSlots()[0];
  // if (uop == nullptr) {
  //   return;
  // }

  // auto sourceRegisters = uop->getOperandRegisters();
  // for (size_t i = 0; i < registers.size(); i++) {
  //   // Check each forwarded register vs source operands and supply for each
  //   // match
  //   for (size_t operand = 0; operand < sourceRegisters.size(); operand++) {
  //     const auto& sourceReg = sourceRegisters[operand];
  //     if (uop->canExecute()) {
  //       return;
  //     }
  //     if (sourceReg == registers[i] && !uop->isOperandReady(operand)) {
  //       // Supply the operand
  //       uop->supplyOperand(operand, values[i]);
  //     }
  //   }
  // }
}

bool Core::canIssue(const std::shared_ptr<Instruction>& uop) {
  if (uop->isSysCall() && inorderIQ_.size() > 0) {
    return false;
  }
  if((uop->isLoad() || uop->isStoreData()) && loadStoreQueue_.isBusy()) {
    return false;
  }
  if (regDepMap_.canRead(uop) && regDepMap_.canWrite(uop)) {
    regDepMap_.insert(uop);
    return true;
  }
  return false;
}

void Core::removeDep(const std::shared_ptr<Instruction>& uop) {
  regDepMap_.remove(uop);
}

void Core::readRegisters() {
  if (decodeToExecuteBuffer_.isStalled()) {
    return;
  }

  const auto& uop = decodeToExecuteBuffer_.getTailSlots()[0];
  if (uop == nullptr) {
    return;
  }

  // Register read
  // Identify missing registers and supply values
  const auto& sourceRegisters = uop->getOperandRegisters();
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    const auto& reg = sourceRegisters[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(i, registerFileSet_.get(reg));
    }
  }
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

void Core::handleLoad(const std::shared_ptr<Instruction>& instruction) {
  loadData(instruction);
  if (instruction->exceptionEncountered()) {
    raiseException(instruction);
    return;
  }

  forwardOperands(instruction->getDestinationRegisters(),
                  instruction->getResults());
  // Manually add the instruction to the writeback input buffer
  completionSlots_[1].getTailSlots()[0] = instruction;
}

void Core::addInstrOrderQ(const std::shared_ptr<Instruction>& insn) {
  //std::cout << std::dec << ticks_ << ": Adding instruction at address: 0x" << std::hex << insn->getInstructionAddress() << std::endl;
  inorderIQ_.push_back(insn);
}

bool Core::removeInstrOrderQ(const std::shared_ptr<Instruction>& insn) {
  if (insn == inorderIQ_.front()) {
    //std::cout << std::dec << ticks_ << ": Removing instruction at address: 0x" << std::hex << insn->getInstructionAddress() << std::endl;
    // if(insn->exceptionEncountered()) {
    //   exceptionGenerated_ = true;
    //   exceptionGeneratingInstruction_ = insn;
    //   handleException();
    // }
    inorderIQ_.pop_front();
    return true;
  } else {
    return false;
  }
}

int16_t Core::isInterruptPending() {
  if (interruptId_>=0) {
    std::cout << std::dec << "[SimEng:Core] Interrupt Pending id: " << interruptId_ << ", at tick: " << ticks_ << std::endl;
    return interruptId_;
  } else {
    return -1;
  }
}

}  // namespace mcu
}  // namespace models
}  // namespace simeng
