#pragma once

#include "../Architecture.hh"
#include "../PipelineBuffer.hh"

namespace simeng {
namespace inorder {

/** A decode unit for an in-order pipeline. Splits pre-decoded macro-ops into
 * uops, and reads operand values. */
class DecodeUnit {
 public:
  /** Constructs a decode unit with references to input/output buffers, the
   * register file set, and the current branch predictor. */
  DecodeUnit(PipelineBuffer<MacroOp>& fromFetch,
             PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
             const RegisterFileSet& registerFileSet,
             BranchPredictor& predictor);

  /** Ticks the decode unit. Breaks macro-ops into uops, and performs early
   * branch misprediction checks. */
  void tick();

  /** Reads and supplies missing source operands for the uop in the output slot.
   */
  void readRegisters();

  /** Forwards operands and performs register reads for the currently queued
   * instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

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

  /** A reference to the register file set. */
  const RegisterFileSet& registerFileSet;

  /** A reference to the current branch predictor. */
  BranchPredictor& predictor;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be updated to upon flush. */
  uint64_t pc;
};

}  // namespace inorder
}  // namespace simeng
