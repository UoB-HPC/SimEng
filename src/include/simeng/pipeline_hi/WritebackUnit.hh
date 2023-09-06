#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/pipeline_hi/PipelineBuffer.hh"
#include <deque>

namespace simeng {
namespace pipeline_hi {

/** A writeback pipeline unit. Responsible for writing instruction results to
 * the register files. */
class WritebackUnit {
 public:
  /** Constructs a writeback unit with references to an input buffer and
   * register file to write to. */
  WritebackUnit(std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>&
                    completionSlots,
                RegisterFileSet& registerFileSet,
                std::function<void(uint64_t insnId)> flagMicroOpCommits,
                std::function<void(const std::shared_ptr<Instruction>&)> removeDep,
                std::function<bool(const std::shared_ptr<Instruction>&)> removeInstrOrderQ);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of instructions retired. */
  uint64_t getInstructionsWrittenCount() const;

  /** Retrieve instruction(s) to be printed out to the trace */
  std::vector<std::shared_ptr<Instruction>> getInstsForTrace();

  /** Clear the container for tracing */
  void traceFinished(); //Might be safer to update trace within WritebackUnit

 private:
  /** Buffers of completed instructions to process. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots_;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet_;

  /** A function handle called to determine if uops associated to an instruction
   * ID can now be committed. */
  std::function<void(uint64_t insnId)> flagMicroOpCommits_;

    /** A function to remove the commited instruction from dependency queue. */
  std::function<void(const std::shared_ptr<Instruction>&)> removeDep_;

    /** A function to remove the commited instruction from ordering queue. */
  std::function<bool(const std::shared_ptr<Instruction>&)> removeInstrOrderQ_;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsWritten_ = 0;

  /** Instruction(s) to be printed out to the trace */
  std::deque<std::shared_ptr<Instruction>> committedInstsForTrace_;
};

}  // namespace pipeline_hi
}  // namespace simeng
