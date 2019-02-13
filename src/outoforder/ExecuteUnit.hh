#pragma once

#include <queue>

#include "../BranchPredictor.hh"
#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "DispatchIssueUnit.hh"
#include "LoadStoreQueue.hh"

namespace simeng {
namespace outoforder {

/** An execution unit pipeline entry, containing an instruction, and an
 * indication of when it's reached the front of the execution pipeline. */
struct ExecutionUnitPipelineEntry {
  /** The instruction queued for execution. */
  std::shared_ptr<Instruction> insn;
  /** The tick number this instruction will reach the front of the queue at. */
  uint64_t readyAt;
};

/** An execute unit for an out-of-order pipeline. Executes instructions and
 * forwards results to the dispatch/issue stage. */
class ExecuteUnit {
 public:
  /** Constructs an execute unit with references to an input and output buffer,
   * the decode unit, the currently used branch predictor, and a pointer to
   * process memory. */
  ExecuteUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromIssue,
              PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
              DispatchIssueUnit& dispatchIssueUnit, LoadStoreQueue& lsq,
              BranchPredictor& predictor);

  /** Tick the execute unit. Places incoming instructions into the pipeline and
   * executes an instruction that has reached the head of the pipeline, if
   * present. */
  void tick();

  /** Query whether a branch misprediction was discovered this cycle. */
  bool shouldFlush() const;

  /** Retrieve the target instruction address associated with the most recently
   * discovered misprediction. */
  uint64_t getFlushAddress() const;

  /** Retrieve the sequence ID associated with the most recently discovered
   * misprediction. */
  uint64_t getFlushSeqId() const;

 private:
  /** Execute the supplied uop, write it into the output buffer, and forward
   * results back to dispatch/issue. */
  void execute(std::shared_ptr<Instruction>& uop);

  /** A buffer of instructions to execute. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromIssueBuffer;

  /** A buffer for writing executed instructions into. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toWritebackBuffer;

  /** A reference to the decode unit, for forwarding operands. */
  DispatchIssueUnit& dispatchIssueUnit;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq;

  /** A reference to the branch predictor, for updating with prediction results.
   */
  BranchPredictor& predictor;

  /** The execution unit's internal pipeline, holding instructions until their
   * execution latency has expired and they are ready for their final results to
   * be calculated and forwarded. */
  std::queue<ExecutionUnitPipelineEntry> pipeline;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be reset to after this cycle.
   */
  uint64_t pc;

  /** The sequence ID of the youngest instruction that should remain after the
   * current flush. */
  uint64_t flushAfter;

  /** The number of times this unit has been ticked. */
  uint64_t tickCounter = 0;
};

}  // namespace outoforder
}  // namespace simeng
