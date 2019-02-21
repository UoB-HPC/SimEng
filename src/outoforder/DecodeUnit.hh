#pragma once

#include "../Architecture.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace outoforder {

/** A decode unit for an out-of-order pipeline. Splits pre-decoded macro-ops
 * into uops. */
class DecodeUnit {
 public:
  /** Constructs a decode unit with references to input/output buffers, the
   * register file, and the current branch predictor. */
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch,
             PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchIssue,
             BranchPredictor& predictor);

  /** Ticks the decode unit. Breaks macro-ops into uops, and performs early
   * branch misprediction checks. */
  void tick();

  /** Check whether the core should be flushed this cycle. */
  bool shouldFlush() const;

  /** Retrieve the target instruction address associated with the most recently
   * discovered misprediction. */
  uint64_t getFlushAddress() const;

  uint64_t getEarlyFlushes() const;

 private:
  /** A buffer of macro-ops to split into uops. */
  PipelineBuffer<MacroOp>& fromFetchBuffer;
  /** A buffer for writing decoded uops into. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchIssueBuffer;

  /** A reference to the current branch predictor. */
  BranchPredictor& predictor;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be updated to upon flush. */
  uint64_t pc;

  uint64_t earlyFlushes = 0;
};

}  // namespace outoforder
}  // namespace simeng
