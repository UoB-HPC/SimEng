#include "Core.hh"

#include <iostream>

namespace simeng {

Core::Core(char* insnPtr, unsigned int programByteLength, Architecture& isa, BranchPredictor& branchPredictor) :
  memory(static_cast<char*>(calloc(1024, 1))),
  registerFile({32, 32, 1}),
  fetchToDecodeBuffer(1, {}),
  decodeToExecuteBuffer(1, nullptr),
  executeToWritebackBuffer(1, nullptr),
  fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa, branchPredictor),
  decodeUnit(fetchToDecodeBuffer, decodeToExecuteBuffer, registerFile),
  executeUnit(decodeToExecuteBuffer, executeToWritebackBuffer, decodeUnit, memory),
  writebackUnit(executeToWritebackBuffer, registerFile)
  {};

void Core::tick() {

  // Writeback must be ticked at start of cycle, to ensure decode reads the correct values
  writebackUnit.tick();

  // Tick units
  fetchUnit.tick();
  decodeUnit.tick();
  executeUnit.tick();

  // Tick buffers
  fetchToDecodeBuffer.tick();
  decodeToExecuteBuffer.tick();
  executeToWritebackBuffer.tick();

  // Check for flush
  auto [executeShouldFlush, executeFlushAddress] = executeUnit.shouldFlush();
  auto [decodeShouldFlush, decodeFlushAddress] = decodeUnit.shouldFlush();
  if (executeShouldFlush) {
    // Flush was requested at execute stage
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Execute)
    fetchUnit.updatePC(executeFlushAddress);
    fetchToDecodeBuffer.fill({});
    decodeToExecuteBuffer.fill(nullptr);
  } else if (decodeShouldFlush) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    fetchUnit.updatePC(decodeFlushAddress);
    fetchToDecodeBuffer.fill({});
  }
}

bool Core::hasHalted() const {
  bool decodePending = fetchToDecodeBuffer.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer.getHeadSlots()[0] != nullptr;
  bool writebackPending = executeToWritebackBuffer.getHeadSlots()[0] != nullptr;

  // std::cout << "hasHalted: " << fetchUnit.hasHalted() << !decodePending << !executePending << !writebackPending << std::endl;

  return (fetchUnit.hasHalted() && !decodePending && !writebackPending && !executePending);
}

}
