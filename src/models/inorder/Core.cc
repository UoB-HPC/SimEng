#include "Core.hh"

#include <string>

namespace simeng {
namespace models {
namespace inorder {

// TODO: Replace simple process memory space with memory hierarchy interface.
Core::Core(const span<char> processMemory, uint64_t entryPoint,
           const Architecture& isa, BranchPredictor& branchPredictor)
    : processMemory_(processMemory),
      isa_(isa),
      registerFileSet_(isa.getRegisterFileStructures()),
      fetchToDecodeBuffer_(1, {}),
      decodeToExecuteBuffer_(1, nullptr),
      completionSlots_(1, {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, processMemory.data(),
                 processMemory.size(), entryPoint, isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToExecuteBuffer_,
                  branchPredictor),
      executeUnit_(
          decodeToExecuteBuffer_, completionSlots_[0],
          [this](auto regs, auto values) { forwardOperands(regs, values); },
          [this](auto instruction) { loadData(instruction); },
          [this](auto instruction) { storeData(instruction); },
          [this](auto instruction) { raiseException(instruction); },
          branchPredictor),
      writebackUnit_(completionSlots_, registerFileSet_) {
  // Query and apply initial state
  auto state = isa.getInitialState(processMemory);
  for (size_t i = 0; i < state.modifiedRegisters.size(); i++) {
    registerFileSet_.set(state.modifiedRegisters[i],
                         state.modifiedRegisterValues[i]);
  }
};

void Core::tick() {
  ticks_++;

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();

  // Tick units
  fetchUnit_.tick();
  decodeUnit_.tick();
  executeUnit_.tick();

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
    return;
  }

  // Check for flush
  if (executeUnit_.shouldFlush()) {
    // Flush was requested at execute stage
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Execute)
    auto targetAddress = executeUnit_.getFlushAddress();

    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    decodeToExecuteBuffer_.fill(nullptr);

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

    flushes_++;
  }
}

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
  bool decodePending = fetchToDecodeBuffer_.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer_.getHeadSlots()[0] != nullptr;
  bool writebackPending = completionSlots_[0].getHeadSlots()[0] != nullptr;

  return (fetchUnit_.hasHalted() && !decodePending && !writebackPending &&
          !executePending);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit_.getInstructionsWrittenCount();
  auto ipc = retired / static_cast<float>(ticks_);
  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
          {"flushes", std::to_string(flushes_)}};
}

void Core::raiseException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  exceptionGenerated_ = false;
  hasHalted_ = true;
  isa_.handleException(exceptionGeneratingInstruction_, registerFileSet_,
                       processMemory_.data());

  std::cout << "Halting due to fatal exception" << std::endl;
}

void Core::loadData(const std::shared_ptr<Instruction>& instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  for (const auto& request : addresses) {
    // Copy the data at the requested memory address into a
    // RegisterValue
    auto data =
        RegisterValue(processMemory_.data() + request.first, request.second);

    instruction->supplyData(request.first, data);
  }
}

void Core::storeData(const std::shared_ptr<Instruction>& instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  const auto& data = instruction->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    const auto& request = addresses[i];

    // Copy data to memory
    auto address = processMemory_.data() + request.first;
    memcpy(address, data[i].getAsVector<char>(), request.second);
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

  for (size_t i = 0; i < registers.size(); i++) {
    if (uop->canExecute()) {
      return;
    }
    uop->supplyOperand(registers[i], values[i]);
  }
}

void Core::readRegisters() {
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
      uop->supplyOperand(reg, registerFileSet_.get(reg));
    }
  }
}

}  // namespace inorder
}  // namespace models
}  // namespace simeng
