#include "Core.hh"

#include <iostream>

namespace simeng {

Core::Core(char* insnPtr, unsigned int programByteLength, Architecture& isa,
           BranchPredictor& branchPredictor)
    : memory(static_cast<char*>(calloc(1024, 1))),
      registerFile({32, 32, 1}),
      fetchToDecodeBuffer(1, {}),
      decodeToExecuteBuffer(1, nullptr),
      executeToWritebackBuffer(1, nullptr),
      fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa,
                branchPredictor),
      decodeUnit(fetchToDecodeBuffer, decodeToExecuteBuffer, registerFile,
                 branchPredictor),
      executeUnit(decodeToExecuteBuffer, executeToWritebackBuffer, decodeUnit,
                  branchPredictor, memory),
      writebackUnit(executeToWritebackBuffer, registerFile){};

void Core::tick() {
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

int Core::getFlushesCount() const { return flushes; }
int Core::getInstructionsRetiredCount() const {
  return writebackUnit.getInstructionsRetiredCount();
}

}  // namespace simeng
