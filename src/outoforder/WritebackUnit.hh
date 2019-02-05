#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

/** An out-of-order pipeline writeback unit. Responsible for handling writing
 * instruction results to the register file. */
class WritebackUnit {
 public:
  /** Constructs a writeback unit with references to an input buffer and
   * register file to write to. */
  WritebackUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromExecute,
                RegisterFile& registerFile);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const;

 private:
  /** A buffer of instructions to process, coming from the execute unit. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromExecuteBuffer;

  /** The register file to write results into. */
  RegisterFile& registerFile;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsRetired = 0;
};

}  // namespace outoforder
}  // namespace simeng
