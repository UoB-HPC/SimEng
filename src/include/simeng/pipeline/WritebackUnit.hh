#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/Statistics.hh"
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
                std::function<void(uint64_t insnId)> flagMicroOpCommits,
                Statistics& stats);

  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();

  /** Retrieve a count of the number of uops processed by the unit. */
  uint64_t getuopsWrittenCount() const;

  /** Retrieve a count of the number of Mops processed by the unit. */
  uint64_t getMopsWrittenCount() const;

 private:
  /** Buffers of completed instructions to process. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots_;

  /** The register file set to write results into. */
  RegisterFileSet& registerFileSet_;

  /** A function handle called to determine if uops associated to an instruction
   * ID can now be committed. */
  std::function<void(uint64_t insnId)> flagMicroOpCommits_;

  /** A reference to the Statistics class. */
  Statistics& stats_;

  /** Statistics class id for the number of micro-ops processed by this stage.
   */
  uint64_t uopsWrittenCntr_;

  /** Statistics class id for the number of macro-ops processed by this stage.
   */
  uint64_t mopsWrittenCntr_;
};

}  // namespace pipeline
}  // namespace simeng
