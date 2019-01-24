#pragma once

#include "PipelineBuffer.hh"
#include "Architecture.hh"

namespace simeng {

class DecodeUnit {
 public:
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch, PipelineBuffer<std::shared_ptr<Instruction>>& toExecute, RegisterFile& registerFile);

  void tick();
  void forwardOperands(std::vector<Register> destinations, std::vector<RegisterValue> values);
 private:
  PipelineBuffer<MacroOp>& fromFetchBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  RegisterFile& registerFile;
};

} // namespace simeng
