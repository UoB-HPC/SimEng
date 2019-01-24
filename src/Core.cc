#include "Core.hh"

#include <iostream>

namespace simeng {

Core::Core(char* insnPtr, unsigned int programByteLength, Architecture& isa) :
  memory(static_cast<char*>(calloc(1024, 1))),
  registerFile({32, 32, 1}),
  fetchToDecodeBuffer(1, {}),
  decodeToExecuteBuffer(1, nullptr),
  executeToWritebackBuffer(1, nullptr),
  fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa),
  decodeUnit(fetchToDecodeBuffer, decodeToExecuteBuffer, registerFile),
  executeUnit(decodeToExecuteBuffer, executeToWritebackBuffer, decodeUnit, memory),
  writebackUnit(executeToWritebackBuffer, registerFile)
  {};

void Core::tick() {

  // Writeback must be ticked at start of cycle
  writebackUnit.tick();

  // Tick units
  fetchUnit.tick();
  decodeUnit.tick();
  executeUnit.tick();

  // Tick buffers
  fetchToDecodeBuffer.tick();
  decodeToExecuteBuffer.tick();
  executeToWritebackBuffer.tick();
}

bool Core::hasHalted() const {
  bool decodePending = fetchToDecodeBuffer.getHeadSlots()[0].size() > 0;
  bool executePending = decodeToExecuteBuffer.getHeadSlots()[0] != nullptr;
  bool writebackPending = executeToWritebackBuffer.getHeadSlots()[0] != nullptr;

  return (fetchUnit.hasHalted() && !decodePending && !writebackPending && !executePending);
}

}
