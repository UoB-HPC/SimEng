#pragma once

#include "PipelineBuffer.hh"
#include "Instruction.hh"

namespace simeng {

class WritebackUnit {
 public:
  WritebackUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromExecute, RegisterFile& registerFile);

  void tick();
 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromExecuteBuffer;

  RegisterFile& registerFile;
};

} // namespace simeng
