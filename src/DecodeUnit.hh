#pragma once

#include "PipelineBuffer.hh"
#include "Architecture.hh"

namespace simeng {

class DecodeUnit {
 public:
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch, PipelineBuffer<std::shared_ptr<Instruction>>& toExecute, RegisterFile& registerFile);

  void tick();
  void forwardOperands(std::vector<Register> destinations, std::vector<RegisterValue> values);
  std::tuple<bool, uint64_t> shouldFlush() const;
 private:
  PipelineBuffer<MacroOp>& fromFetchBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  RegisterFile& registerFile;

  bool shouldFlush_;
  uint64_t pc;
};

} // namespace simeng
