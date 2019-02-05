#pragma once

#include <deque>

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

/** A dispatch/issue unit for an out-of-order pipeline. Reads instruction
 * operand and performs scoreboarding. Issues instructions to the execution unit
 * once ready. */
class DispatchIssueUnit {
 public:
  /** Construc a dispatch/issue unit with references to input/output buffers,
   * the register file, and a description of the number of physical registers
   * the scoreboard needs to reflect. */
  DispatchIssueUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
                    PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
                    const RegisterFile& registerFile,
                    const std::vector<uint16_t>& physicalRegisterStructure);

  /** Ticks the dispatch/issue unit. Reads available input operands for
   * instructions and sets scoreboard flags for destination registers. */
  void tick();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const std::vector<Register>& destinations,
                       const std::vector<RegisterValue>& values);

  /** Set the scoreboard entry for the provided register as ready. */
  void setRegisterReady(Register reg);

 private:
  /** A buffer of instructions to dispatch and read operands for. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromRenameBuffer;

  /** A buffer for writing ready instructions to. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  /** A reference to the physical register file. */
  const RegisterFile& registerFile;

  /** The register availability scoreboard. */
  std::vector<std::vector<bool>> scoreboard;

  /** The reservation station. Holds instructions until operands become
   * available. */
  std::deque<std::shared_ptr<Instruction>> reservationStation;
};

}  // namespace outoforder
}  // namespace simeng
