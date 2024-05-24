#pragma once

#include <deque>
#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

/** An execution unit pipeline entry, containing an instruction, and an
 * indication of when it's reached the front of the execution pipeline. */
struct ExecutionUnitPipelineEntry {
  /** The instruction queued for execution. */
  std::shared_ptr<Instruction> insn;
  /** The tick number this instruction will reach the front of the queue at. */
  uint64_t readyAt;
};

/** An execute unit for a pipelined processor. Executes instructions and
 * forwards results. */
class ExecuteUnit {
 public:
  /** Constructs an execute unit with references to an input and output buffer,
   * the currently used branch predictor, and handlers for forwarding operands,
   * loads/stores, and exceptions. */
  ExecuteUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& input,
      PipelineBuffer<std::shared_ptr<Instruction>>& output,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      std::function<void(const std::shared_ptr<Instruction>&)> handleLoad,
      std::function<void(const std::shared_ptr<Instruction>&)> handleStore,
      std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
      bool pipelined = true, const std::vector<uint16_t>& blockingGroups = {});

  /** Tick the execute unit. Places incoming instructions into the pipeline and
   * executes an instruction that has reached the head of the pipeline, if
   * present. */
  void tick();

  /** Query whether a branch misprediction was discovered this cycle. */
  bool shouldFlush() const;

  /** Retrieve the target instruction address associated with the most recently
   * discovered misprediction. */
  uint64_t getFlushAddress() const;

  /** Retrieve the instruction ID associated with the most recently discovered
   * misprediction. */
  uint64_t getFlushInsnId() const;

  /** Purge flushed instructions from the internal pipeline and clear any active
   * stall, if applicable. */
  void purgeFlushed();

  /** Retrieve the number of active execution cycles. */
  uint64_t getCycles() const;

  /** Query whether the execution unit is empty and not currently processing any
   * instructions. */
  bool isEmpty() const;

 private:
  /** Execute the supplied uop, write it into the output buffer, and forward
   * results back to dispatch/issue. */
  void execute(std::shared_ptr<Instruction>& uop);

  /** A buffer of instructions to execute. */
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** A buffer for writing executed instructions into. */
  PipelineBuffer<std::shared_ptr<Instruction>>& output_;

  /** A function handle called when forwarding operands. */
  std::function<void(span<Register>, span<RegisterValue>)> forwardOperands_;

  /** A function handle called after generating the addresses for a load. */
  std::function<void(const std::shared_ptr<Instruction>&)> handleLoad_;
  /** A function handle called after acquiring the data for a store. */
  std::function<void(const std::shared_ptr<Instruction>&)> handleStore_;

  /** A function handle called upon exception generation. */
  std::function<void(const std::shared_ptr<Instruction>&)> raiseException_;

  /** Whether this unit is pipelined, or if all instructions should stall until
   * complete. */
  bool pipelined_;

  /** The execution unit's internal pipeline, holding instructions until their
   * execution latency has expired and they are ready for their final results to
   * be calculated and forwarded. */
  std::deque<ExecutionUnitPipelineEntry> pipeline_;

  /** A group of operation types that are blocked whilst a similar operation
   * is being executed. */
  std::vector<uint16_t> blockingGroups_;

  /** A queue to hold blocked instructions of a similar group type to
   * blockingGroup_. */
  std::deque<std::shared_ptr<Instruction>> operationsStalled_;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_ = false;

  /** The target instruction address the PC should be reset to after this cycle.
   */
  uint64_t pc_;

  /** The sequence ID of the youngest instruction that should remain after the
   * current flush. */
  uint64_t flushAfter_;

  /** The number of times this unit has been ticked. */
  uint64_t tickCounter_ = 0;

  /** The cycle this unit will become unstalled. */
  uint64_t stallUntil_ = 0;

  /** The number of active execution cycles that were observed. */
  uint64_t cycles_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
