#pragma once

#include "../Instruction.hh"
#include "PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** A writeback pipeline unit. Responsible for writing instruction results to
 * the register files. */
class WritebackUnit {
 public:
  /** Constructs a writeback unit with references to an input buffer and
   * register file to write to. */
  WritebackUnit(std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>&
                    completionSlots,
                RegisterFileSet& registerFileSet);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of instructions retired. */
  uint64_t getInstructionsWrittenCount() const;

 private:
  /** Buffers of completed instructions to process. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots_;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet_;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsWritten_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
