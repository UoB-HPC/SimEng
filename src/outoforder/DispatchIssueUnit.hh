#pragma once

#include <deque>

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

class DispatchIssueUnit {
 public:
  DispatchIssueUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
                    PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
                    const RegisterFile& registerFile,
                    const std::vector<uint16_t>& physicalRegisterStructure);
  void tick();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const std::vector<Register>& destinations,
                       const std::vector<RegisterValue>& values);

  void setRegisterReady(Register reg);

 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromRenameBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  const RegisterFile& registerFile;
  std::vector<std::vector<bool>> scoreboard;

  std::deque<std::shared_ptr<Instruction>> reservationStation;
};

}  // namespace outoforder
}  // namespace simeng
