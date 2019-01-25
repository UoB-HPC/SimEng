#pragma once

#include "PipelineBuffer.hh"
#include "Architecture.hh"

namespace simeng {

class DecodeUnit {
 public:
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch, PipelineBuffer<std::shared_ptr<Instruction>>& toExecute, RegisterFile& registerFile, BranchPredictor& predictor);

  void tick();
  void forwardOperands(std::vector<Register> destinations, std::vector<RegisterValue> values);
  bool shouldFlush() const;
  uint64_t getFlushAddress() const;
 private:
  PipelineBuffer<MacroOp>& fromFetchBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  RegisterFile& registerFile;
  BranchPredictor& predictor;

  bool shouldFlush_;
  uint64_t pc;
};

} // namespace simeng
