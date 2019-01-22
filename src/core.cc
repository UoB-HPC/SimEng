#include "core.hh"

namespace simeng {

Core::Core(char* insnPtr, int programByteLength, Architecture* isa) : fetchToDecodeBuffer(1), fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa) {};

void Core::tick() {

  // Tick units
  fetchUnit.tick();

  // Tick buffers
  fetchToDecodeBuffer.tick();
}

}
