#pragma once

#include <vector>

#include "FetchUnit.hh"
#include "DecodeUnit.hh"
#include "ExecuteUnit.hh"
#include "WritebackUnit.hh"

namespace simeng {

class Core {
 public:
  Core(char* insnPtr, unsigned int programByteLength, Architecture& isa, BranchPredictor& branchPredictor);
  void tick();

  bool hasHalted() const;
 private:
  char* memory;

  RegisterFile registerFile;

  PipelineBuffer<MacroOp> fetchToDecodeBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>> decodeToExecuteBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>> executeToWritebackBuffer;

  FetchUnit fetchUnit;
  DecodeUnit decodeUnit;
  ExecuteUnit executeUnit;
  WritebackUnit writebackUnit;
};

} // namespace simeng
