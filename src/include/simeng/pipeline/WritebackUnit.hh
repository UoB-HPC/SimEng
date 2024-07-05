#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

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
                RegisterFileSet& registerFileSet,
                std::function<void(uint64_t insnId)> flagMicroOpCommits);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of instructions retired. */
  uint64_t getInstructionsWrittenCount() const;

  /** Retrieve a count of the number of load instructions retired. */
  uint64_t getLoadInstructionsWrittenCount() const;

  /** Retrieve a count of the number of store instructions retired. */
  uint64_t getStoreInstructionsWrittenCount() const;

 private:
  /** Buffers of completed instructions to process. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots_;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet_;

  /** A function handle called to determine if uops associated to an instruction
   * ID can now be committed. */
  std::function<void(uint64_t insnId)> flagMicroOpCommits_;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsWritten_ = 0;

  /** The number of load instructions processed and retired by this stage. */
  uint64_t loadInstructionsWritten_ = 0;

  /** The number of store instructions processed and retired by this stage. */
  uint64_t storeInstructionsWritten_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
