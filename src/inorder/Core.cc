#include "Core.hh"

#include <string>

namespace simeng {
namespace inorder {

// TODO: Replace simple process memory space with memory hierarchy interface.
Core::Core(const span<char> processMemory, uint64_t entryPoint,
           const Architecture& isa, BranchPredictor& branchPredictor)
    : processMemory_(processMemory),
      isa(isa),
      registerFileSet(isa.getRegisterFileStructures()),
      fetchToDecodeBuffer(1, {}),
      decodeToExecuteBuffer(1, nullptr),
      completionSlots(1, {1, nullptr}),
      fetchUnit(fetchToDecodeBuffer, processMemory.data(), processMemory.size(),
                entryPoint, isa, branchPredictor),
      decodeUnit(fetchToDecodeBuffer, decodeToExecuteBuffer, registerFileSet,
                 branchPredictor),
      executeUnit(
          decodeToExecuteBuffer, completionSlots[0],
          [this](auto regs, auto values) {
            return decodeUnit.forwardOperands(regs, values);
          },
          [this](auto instruction) { loadData(instruction); },
          [this](auto instruction) { storeData(instruction); },
          [this](auto instruction) { raiseException(instruction); },
          branchPredictor),
      writebackUnit(completionSlots, registerFileSet){};

void Core::tick() {
  ticks++;

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit.tick();

  // Tick units
  fetchUnit.tick();
  decodeUnit.tick();
  executeUnit.tick();

  // Read pending registers for ready-to-execute uop; must happen after execute
  // to allow operand forwarding to take place first
  decodeUnit.readRegisters();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer.tick();
  decodeToExecuteBuffer.tick();
  for (auto& buffer : completionSlots) {
    buffer.tick();
  }

  if (exceptionGenerated_) {
    handleException();
    return;
  }

  // Check for flush
  if (executeUnit.shouldFlush()) {
    // Flush was requested at execute stage
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Execute)
    auto targetAddress = executeUnit.getFlushAddress();

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});
    decodeToExecuteBuffer.fill(nullptr);

    flushes++;
  } else if (decodeUnit.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit.getFlushAddress();

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});

    flushes++;
  }
}

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
  bool decodePending = fetchToDecodeBuffer.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer.getHeadSlots()[0] != nullptr;
  bool writebackPending = completionSlots[0].getHeadSlots()[0] != nullptr;

  return (fetchUnit.hasHalted() && !decodePending && !writebackPending &&
          !executePending);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit.getInstructionsWrittenCount();
  auto ipc = retired / static_cast<float>(ticks);
  return {{"cycles", std::to_string(ticks)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
          {"flushes", std::to_string(flushes)}};
}

void Core::raiseException(std::shared_ptr<Instruction> instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  exceptionGenerated_ = false;
  hasHalted_ = true;
  isa.handleException(exceptionGeneratingInstruction_);

  std::cout << "Halting due to fatal exception" << std::endl;
}

void Core::loadData(std::shared_ptr<Instruction> instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  for (auto const& request : addresses) {
    // Copy the data at the requested memory address into a
    // RegisterValue
    auto data =
        RegisterValue(processMemory_.data() + request.first, request.second);

    instruction->supplyData(request.first, data);
  }
}

void Core::storeData(std::shared_ptr<Instruction> instruction) {
  const auto& addresses = instruction->getGeneratedAddresses();
  const auto& data = instruction->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    auto& request = addresses[i];

    // Copy data to memory
    auto address = processMemory_.data() + request.first;
    memcpy(address, data[i].getAsVector<char>(), request.second);
  }
}

}  // namespace inorder
}  // namespace simeng
