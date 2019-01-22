#ifndef __H_CORE
#define __H_CORE

#include <vector>

#include "fetchUnit.hh"

namespace simeng {

class Core {
 public:
  Core(char* insnPtr, int programByteLength, Architecture* isa);
  void tick();
 
 private:
  PipelineBuffer<MacroOp> fetchToDecodeBuffer;

  FetchUnit fetchUnit;

};

} // namespace simeng

#endif
