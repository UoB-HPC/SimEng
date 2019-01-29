#pragma once

#include "DecodeUnit.hh"
#include "Instruction.hh"
#include "PipelineBuffer.hh"

namespace simeng {

/** An execute unit for an in-order pipeline. Executes instructions and forwards
 * results to the decode stage. */
class ExecuteUnit {
 public:
  /** Constructs an execute unit with references to an input and output buffer,
   * the decode unit, the currently used branch predictor, and a pointer to
   * process memory. */
  ExecuteUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
              PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
              DecodeUnit& decodeUnit, BranchPredictor& predictor, char* memory);

  /** Tick the execute unit. Executes the current instruction and forwards the
   * results back to the decode stage. */
  void tick();

  /** Query whether a branch misprediction was discovered this cycle. */
  bool shouldFlush() const;

  /** Retrieve the target instruction address associated with the most recently
   * discovered misprediction. */
  uint64_t getFlushAddress() const;

 private:
  /** A buffer of instructions to execute. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;

  /** A buffer for writing executed instructions into. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toWritebackBuffer;

  /** A reference to the decode unit, for forwarding operands. */
  DecodeUnit& decodeUnit;

  /** A reference to the branch predictor, for updating with prediction results.
   */
  BranchPredictor& predictor;

  /** A pointer to process memory. */
  char* memory;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be reset to after this cycle.
   */
  uint64_t pc;
};

}  // namespace simeng
