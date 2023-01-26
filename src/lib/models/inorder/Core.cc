#include "simeng/models/inorder/Core.hh"

#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

namespace simeng {
namespace models {
namespace inorder {

// TODO: Replace with config options
const unsigned int blockSize = 16;
const unsigned int clockFrequency = 2.5 * 1e9;

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           const arch::Architecture& isa, BranchPredictor& branchPredictor)
    : dataMemory_(dataMemory),
      isa_(isa),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_),
      fetchToDecodeBuffer_(1, {}),
      decodeToExecuteBuffer_(1, nullptr),
      completionSlots_(1, {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, blockSize, isa,
                 branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToExecuteBuffer_,
                  branchPredictor),
      executeUnit_(
          decodeToExecuteBuffer_, completionSlots_[0],
          [this](auto regs, auto values) { forwardOperands(regs, values); },
          [this](auto instruction) { handleLoad(instruction); },
          [this](auto instruction) { storeData(instruction); },
          [this](auto instruction) { raiseException(instruction); },
          branchPredictor, false),
      writebackUnit_(completionSlots_, registerFileSet_, [](auto insnId) {}){};

void Core::tick() {
  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

  switch (status_) {
    case CoreStatus::idle:
      idle_ticks_++;
      return;
    case CoreStatus::switching: {
      if (fetchToDecodeBuffer_.isEmpty({}) &&
          decodeToExecuteBuffer_.isEmpty(nullptr) &&
          completionSlots_[0].isEmpty(nullptr) &&
          (exceptionHandler_ == nullptr)) {
        // Flush pipeline
        fetchUnit_.flushLoopBuffer();
        decodeUnit_.purgeFlushed();
        executeUnit_.flush();
        previousAddresses_ = std::queue<simeng::MemoryAccessTarget>();
        status_ = CoreStatus::idle;
        return;
      }
      break;
    }
    case CoreStatus::halted:
      return;
    default:
      break;
  }

  // Increase tick count for current process execution
  procTicks_++;

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();

  // Tick units
  fetchUnit_.tick();
  decodeUnit_.tick();
  executeUnit_.tick();

  // Wipe any data read responses, as they will have been handled by this point
  dataMemory_.clearCompletedReads();

  // Read pending registers for ready-to-execute uop; must happen after execute
  // to allow operand forwarding to take place first
  readRegisters();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer_.tick();
  decodeToExecuteBuffer_.tick();
  for (auto& buffer : completionSlots_) {
    buffer.tick();
  }

  if (exceptionGenerated_) {
    handleException();
    fetchUnit_.requestFromPC();
    return;
  }

  // Check for flush
  if (executeUnit_.shouldFlush()) {
    // Flush was requested at execute stage
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Execute)
    auto targetAddress = executeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    decodeToExecuteBuffer_.fill(nullptr);
    decodeUnit_.purgeFlushed();

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

    flushes_++;
  }

  fetchUnit_.requestFromPC();
}

CoreStatus Core::getStatus() {
  // Core is considered to have halted when the fetch unit has halted, there are
  // no uops at the head of any buffer, and no exception is currently being
  // handled.
  bool decodePending = fetchToDecodeBuffer_.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer_.getHeadSlots()[0] != nullptr;
  bool writebackPending = completionSlots_[0].getHeadSlots()[0] != nullptr;

  if (fetchUnit_.hasHalted() && !decodePending && !writebackPending &&
      !executePending && exceptionHandler_ == nullptr) {
    status_ = CoreStatus::halted;
  }

  return status_;
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
          {"idle.ticks", std::to_string(idle_ticks_)},
          {"context.switches", std::to_string(contextSwitches_)}};
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

  // Flush pipeline
  fetchToDecodeBuffer_.fill({});
  decodeToExecuteBuffer_.fill(nullptr);
  decodeUnit_.purgeFlushed();
  completionSlots_[0].fill(nullptr);
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
    status_ = CoreStatus::halted;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.flushLoopBuffer();
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
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  const auto& uop = decodeToExecuteBuffer_.getTailSlots()[0];
  if (uop == nullptr) {
    return;
  }

  auto sourceRegisters = uop->getOperandRegisters();
  for (size_t i = 0; i < registers.size(); i++) {
    // Check each forwarded register vs source operands and supply for each
    // match
    for (size_t operand = 0; operand < sourceRegisters.size(); operand++) {
      const auto& sourceReg = sourceRegisters[operand];
      if (uop->canExecute()) {
        return;
      }
      if (sourceReg == registers[i] && !uop->isOperandReady(operand)) {
        // Supply the operand
        uop->supplyOperand(operand, values[i]);
      }
    }
  }
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
  completionSlots_[0].getTailSlots()[0] = instruction;
}

void Core::schedule(simeng::kernel::cpuContext newContext) {
  // Zero out all physical registers in underlying registerFileSet
  registerFileSet_.reset(isa_.getRegisterFileStructures());
  currentTID_ = newContext.TID;
  fetchUnit_.setProgramLength(newContext.progByteLen);
  fetchUnit_.updatePC(newContext.pc);
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      registerFileSet_.set({(uint8_t)type, (uint16_t)tag},
                           newContext.regFile[type][tag]);
    }
  }
  status_ = CoreStatus::executing;
  procTicks_ = 0;
  isa_.updateAfterContextSwitch(newContext);
  // Allow fetch unit to resume fetching instructions & incrementing PC
  fetchUnit_.unpause();
}

bool Core::interrupt() {
  if (exceptionHandler_ == nullptr) {
    status_ = CoreStatus::switching;
    contextSwitches_++;
    // Stop fetch unit from incrementing PC or fetching next instructions
    // (also flushes loop buffer and any pending completed reads).
    fetchUnit_.pause();
    return true;
  }
  return false;
}

uint64_t Core::getCurrentProcTicks() const { return procTicks_; }

simeng::kernel::cpuContext Core::getPrevContext() const {
  kernel::cpuContext newContext;
  newContext.TID = currentTID_;
  newContext.pc = writebackUnit_.getNextPC();
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

}  // namespace inorder
}  // namespace models
}  // namespace simeng
