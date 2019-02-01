#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

class DispatchIssueUnit {
 public:
  DispatchIssueUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
                    PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
                    const RegisterFile& registerFile);
  void tick();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const std::vector<Register>& destinations,
                       const std::vector<RegisterValue>& values);

 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromRenameBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  const RegisterFile& registerFile;
};

}  // namespace outoforder
}  // namespace simeng
