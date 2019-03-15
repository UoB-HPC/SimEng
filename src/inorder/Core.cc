#include "Core.hh"

#include <string>

namespace simeng {
namespace inorder {

// TODO: Replace simple process memory space with memory hierarchy interface.
Core::Core(const char* insnPtr, unsigned int programByteLength,
           const Architecture& isa, BranchPredictor& branchPredictor,
           char* memory)
    : registerFileSet(isa.getRegisterFileStructures()),
      fetchToDecodeBuffer(1, {}),
      decodeToExecuteBuffer(1, nullptr),
      executeToWritebackBuffer(1, nullptr),
      fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa,
                branchPredictor),
      decodeUnit(fetchToDecodeBuffer, decodeToExecuteBuffer, registerFileSet,
                 branchPredictor),
      executeUnit(
          decodeToExecuteBuffer, executeToWritebackBuffer,
          [this](auto regs, auto values) {
            return decodeUnit.forwardOperands(regs, values);
          },
          branchPredictor, memory),
      writebackUnit(executeToWritebackBuffer, registerFileSet){};

void Core::tick() {
  ticks++;

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit.tick();

  // Tick units
  fetchUnit.tick();
  decodeUnit.tick();
  executeUnit.tick();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer.tick();
  decodeToExecuteBuffer.tick();
  executeToWritebackBuffer.tick();

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
  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
  bool decodePending = fetchToDecodeBuffer.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer.getHeadSlots()[0] != nullptr;
  bool writebackPending = executeToWritebackBuffer.getHeadSlots()[0] != nullptr;

  return (fetchUnit.hasHalted() && !decodePending && !writebackPending &&
          !executePending);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit.getInstructionsRetiredCount();
  auto ipc = retired / static_cast<float>(ticks);
  return {{"cycles", std::to_string(ticks)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
          {"flushes", std::to_string(flushes)}};
}

}  // namespace inorder
}  // namespace simeng
