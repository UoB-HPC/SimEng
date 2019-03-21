#pragma once

#include <functional>

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "DecodeUnit.hh"

namespace simeng {
namespace inorder {

/** An execute unit for an in-order pipeline. Executes instructions and forwards
 * results by calling the supplied function. */
class ExecuteUnit {
 public:
  /** Constructs an execute unit with references to an input and output buffer,
   * an operand-forwarding function, the currently used branch predictor,
   * and a pointer to process memory. */
  ExecuteUnit(
      PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
      PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
      std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      BranchPredictor& predictor,
      std::function<void(std::shared_ptr<Instruction>)> raiseException,
      char* memory);

  /** Tick the execute unit. Executes the current instruction and forwards the
   * results by calling the operand-forwarding function supplied at
   * construction. */
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

  /** An operand-forwarding function, called with the results of execution. */
  std::function<void(span<Register>, span<RegisterValue>)> forwardOperands;

  /** A reference to the branch predictor, for updating with prediction results.
   */
  BranchPredictor& predictor;

  /** A function to call upon exception generation. */
  std::function<void(std::shared_ptr<Instruction>)> raiseException;

  /** A pointer to process memory. */
  char* memory;

  /** Whether the core should be flushed after this cycle. */
  bool shouldFlush_;

  /** The target instruction address the PC should be reset to after this cycle.
   */
  uint64_t pc;
};

}  // namespace inorder
}  // namespace simeng
