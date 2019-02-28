#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

/** An out-of-order pipeline writeback unit. Responsible for handling writing
 * instruction results to the register files. */
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
  uint64_t getInstructionsRetiredCount() const;

 private:
  /** Buffers of completed instructions to process, coming from the execute
   * units. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsRetired = 0;
};

}  // namespace outoforder
}  // namespace simeng
