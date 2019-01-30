#pragma once

#include "Architecture.hh"
#include "PipelineBuffer.hh"

namespace simeng {

/** A decode unit for an in-order pipeline. Splits pre-decoded macro-ops into
 * uops, and reads operand values. */
class DecodeUnit {
 public:
  /** Constructs a decode unit with references to input/output buffers, the
   * register file, and the current branch predictor. */
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch,
             PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
             const RegisterFile& registerFile,
             BranchPredictor& predictor);

  /** Ticks the decode unit. Breaks macro-ops into uops, and performs early
   * branch misprediction checks. */
  void tick();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const std::vector<Register>& destinations,
                       const std::vector<RegisterValue>& values);

  /** Check whether the core should be flushed this cycle. */
  bool shouldFlush() const;

  /** Retrieve the target instruction address associated with the most recently
   * discovered misprediction. */
  uint64_t getFlushAddress() const;

 private:
  /** A buffer of macro-ops to split into uops. */
  PipelineBuffer<MacroOp>& fromFetchBuffer;
  /** A buffer for writing decoded uops into. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toExecuteBuffer;

  /** A reference to the register file. */
  const RegisterFile& registerFile;

  /** A reference to the current branch predictor. */
  BranchPredictor& predictor;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be updated to upon flush. */
  uint64_t pc;
};

}  // namespace simeng
