#pragma once

#include "PipelineBuffer.hh"
#include "Architecture.hh"

namespace simeng {

class FetchUnit {
 public:
  FetchUnit(PipelineBuffer<MacroOp>& toDecode, char* insnPtr, unsigned int programByteLength, Architecture& isa);

  void tick();
  bool hasHalted() const;
  void updatePC(uint64_t address);
 private:
  PipelineBuffer<MacroOp>& toDecode;

  uint64_t pc = 0;

  char* insnPtr;
  unsigned int programByteLength;
  Architecture& isa;

  bool hasHalted_ = false;
};

} // namespace simeng
