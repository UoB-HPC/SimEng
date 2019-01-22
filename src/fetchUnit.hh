#ifndef __H_FETCH_UNIT
#define __H_FETCH_UNIT

#include "pipelineBuffer.hh"
#include "architecture.hh"

namespace simeng {

class FetchUnit {
 public:
  FetchUnit(PipelineBuffer<MacroOp> &toDecode, char* insnPtr, int programByteLength, Architecture* isa);

  void tick();
  bool hasHalted() const;
 private:
  PipelineBuffer<MacroOp> &toDecode;

  uint64_t pc = 0;

  char* insnPtr;
  int programByteLength;
  Architecture* isa;

  bool hasHalted_;
};

} // namespace simeng

#endif
