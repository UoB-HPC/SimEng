#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** A writeback pipeline unit. Responsible for writing instruction results to
 * the register files. */
class WritebackUnit {
 public:
  /** Constructs a writeback unit with references to an input buffer and
   * register file to write to. */
  WritebackUnit(
      std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>&
          completionSlots,
      RegisterFileSet& registerFileSet,
      std::function<void(Register reg)> setRegisterReady,
      std::function<bool(uint64_t seqId)> canWriteback,
      std::function<void(const std::shared_ptr<Instruction>&)> postWriteback);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of instructions retired. */
  uint64_t getInstructionsWrittenCount() const;

  /** Removes all Instructions from CompletionSlots_. */
  void flush();

 private:
  /** Buffers of completed instructions to process. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots_;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet_;

  /** A function handle to mark the destination registers as ready to be read
   * from by other instructions. */
  std::function<void(Register reg)> setRegisterReady_;

  /** A function handle to query whether a instruction, identified by its unique
   * sequence ID, can writeback. */
  std::function<bool(uint64_t seqId)> canWriteback_;

  /** A function handle to carry out logic, specific to a core/model, after the
   * general writeback logic has been carried out. */
  std::function<void(const std::shared_ptr<Instruction>&)> postWriteback_;

  /** The number of instructions processed and retired by this stage. */
  uint64_t instructionsWritten_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
