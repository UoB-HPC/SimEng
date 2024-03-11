#include "simeng/models/inorder/Core.hh"

#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

namespace simeng {
namespace models {
namespace inorder {

Core::Core(memory::MemoryInterface& instructionMemory,
           memory::MemoryInterface& dataMemory, uint64_t processMemorySize,
           uint64_t entryPoint, const arch::Architecture& isa,
           BranchPredictor& branchPredictor)
    : simeng::Core(dataMemory, isa, config::SimInfo::getArchRegStruct()),
      architecturalRegisterFileSet_(registerFileSet_),
      fetchToDecodeBuffer_(1, {}),
      decodeToExecuteBuffer_(1, nullptr),
      completionSlots_(1, {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint,
                 config::SimInfo::getConfig()["Fetch"]["Fetch-Block-Size"]
                     .as<uint16_t>(),
                 isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToExecuteBuffer_,
                  branchPredictor),
      executeUnit_(
          decodeToExecuteBuffer_, completionSlots_[0],
          [this](auto regs, auto values) { forwardOperands(regs, values); },
          [this](auto instruction) { handleLoad(instruction); },
          [this](auto instruction) { storeData(instruction); },
          [this](auto instruction) { raiseException(instruction); }, false),
      writebackUnit_(completionSlots_, registerFileSet_, [](auto insnId) {}) {
  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
}

void Core::tick() {
  if (hasHalted_) return;

  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

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
  // Only ever 1 completion slot
  completionSlots_[0].tick();

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

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, there
  // are no uops pending in any buffer, the execute unit is not currently
  // processing an instructions and no exception is currently being handled.

  // Units place uops in buffer tail, but if buffer is stalled, uops do not
  // move to head slots and so remain in tail slots. Buffer head appears
  // empty. Check emptiness accordingly
  auto decSlots = fetchToDecodeBuffer_.getPendingSlots()[0];
  bool decodePending = decSlots.size() > 0;

  auto exeSlots = decodeToExecuteBuffer_.getPendingSlots()[0];
  bool executePending = exeSlots != nullptr;

  auto writeSlots = completionSlots_[0].getPendingSlots()[0];
  bool writebackPending = writeSlots != nullptr;

  return (fetchUnit_.hasHalted() && !decodePending && !writebackPending &&
          !executePending && executeUnit_.isEmpty() &&
          exceptionHandler_ == nullptr);
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return writebackUnit_.getInstructionsWrittenCount();
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit_.getInstructionsWrittenCount();
  auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(retired)},
          {"ipc", ipcStr.str()},
          {"flushes", std::to_string(flushes_)}};
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

void Core::loadData(const std::shared_ptr<Instruction>& instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  for (const auto& target : addresses) {
    dataMemory_.requestRead(target);
  }

  // NOTE: This model only supports zero-cycle data memory models, and will
  // not work unless data requests are handled synchronously.
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

  auto sourceRegisters = uop->getSourceRegisters();
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
  const auto& sourceRegisters = uop->getSourceRegisters();
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    const auto& reg = sourceRegisters[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(i, registerFileSet_.get(reg));
    }
  }
}

}  // namespace inorder
}  // namespace models
}  // namespace simeng
