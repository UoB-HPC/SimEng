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
           uint64_t processMemorySize, uint64_t entryPoint,
           const arch::Architecture& isa, BranchPredictor& branchPredictor,
           Statistics& stats)
    : dataMemory_(dataMemory),
      isa_(isa),
      stats_(stats),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_),
      fetchToDecodeBuffer_(1, {}),
      decodeToExecuteBuffer_(1, nullptr),
      completionSlots_(1, {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, blockSize, isa, branchPredictor, stats_),
      decodeUnit_(fetchToDecodeBuffer_, decodeToExecuteBuffer_, branchPredictor,
                  stats_),
      executeUnit_(
          decodeToExecuteBuffer_, completionSlots_[0],
          [this](auto regs, auto values) { forwardOperands(regs, values); },
          [this](auto instruction) { handleLoad(instruction); },
          [this](auto instruction) { storeData(instruction); },
          [this](auto instruction) { raiseException(instruction); },
          branchPredictor, stats_, false),
      writebackUnit_(
          completionSlots_, registerFileSet_, [](auto insnId) {}, stats_) {
  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);

  // Register stat counters
  ticksCntr_ = stats_.registerStat("core.cycles");
  flushesCntr_ = stats_.registerStat("core.flushes");
};

void Core::tick() {
  stats_.incrementStat(ticksCntr_, 1);

  if (hasHalted_) return;

  if (hasHalted_) return;

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

    stats_.incrementStat(flushesCntr_, 1);
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

    stats_.incrementStat(flushesCntr_, 1);
  }

  fetchUnit_.requestFromPC();
  isa_.updateSystemTimerRegisters(&registerFileSet_,
                                  stats_.getFullSimStat(ticksCntr_));
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

  return (fetchUnit_.hasHalted() && !decodePending && !writebackPending &&
          !executePending && exceptionHandler_ == nullptr);
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return writebackUnit_.getuopsWrittenCount();
}

uint64_t Core::getSystemTimer() const {
  // TODO: This will need to be changed if we start supporting DVFS.
  return stats_.getFullSimStat(ticksCntr_) / (clockFrequency / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  std::map<std::string, std::string> finalStatDump = {
      {"branch.executed", "0"},
      {"branch.mispredict", "0"},
      {"core.cycles", "0"},
      {"core.flushes", "0"},
      {"writeback.uopsExecuted", "0"}};
  stats_.fillSimulationStats(finalStatDump);

  // Calculate IPC
  auto ipc = std::stoi(finalStatDump["writeback.uopsExecuted"]) /
             static_cast<float>(stats_.getFullSimStat(ticksCntr_));
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;
  finalStatDump["ipc"] = ipcStr.str();

  // Calculate the branch miss rate
  auto branchMissRate =
      100.0f *
      static_cast<float>(std::stoi(finalStatDump["branch.mispredict"])) /
      static_cast<float>(std::stoi(finalStatDump["branch.executed"]));
  std::ostringstream branchMissRateStr;
  branchMissRateStr << std::setprecision(3) << branchMissRate << "%";
  finalStatDump["branch.missrate"] = branchMissRateStr.str();

  return finalStatDump;
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
    hasHalted_ = true;
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

}  // namespace inorder
}  // namespace models
}  // namespace simeng
