#pragma once

#include <simeng/Instruction.hh>
#include <vector>

#include "PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

// TODO: Documentation
class OffloadingController {
  /** An alias for a `PipelineBuffer` of `Instruction`s. */
  using port = PipelineBuffer<std::shared_ptr<Instruction>>;

  /** An alias for a function handling operator forwarding. */
  using forward_operands =
      std::function<void(span<Register>, span<RegisterValue>)>;

  /** An alias for a function handling raising exceptions. */
  using raise_exception =
      std::function<void(const std::shared_ptr<Instruction>&)>;

  /** A set of instruction groups that should be offloaded to the accelerator.
   */
  using offloaded_groups = std::vector<uint16_t>;

  /** An alias for a function that determines whether an instruction should be
   * diverted to an accelerator or not. */
  using instruction_filter =
      std::function<bool(const std::shared_ptr<Instruction>&)>;

 public:
  OffloadingController(port& input, port& output,
                       forward_operands forwardOperands,
                       raise_exception raiseException,
                       instruction_filter filter);

  /** Returns a port that should be connected to an ExecuteUnit; all
  instructions that are not supposed to be diverted to the accelerator will be
  forwarded to this port. */
  port& getPassThroughPort() noexcept;

  /** Tick the controller. Places incoming instructions into the pipeline and
   * executes an instruction that has reached the head of the pipeline, if
   * present. */
  void tick();


  /** Purge flushed instructions from the internal pipeline. */
  void purgeFlushed();
  // TODO: What should happen when flushing? How to flush the accelerator?

  // TODO: What happens if an instruction on the accelerator causes a flush
  //       (separate from exceptions)? Should that even be possible?

 private:
  /** A buffer of instructions to inspect. */
  port& input_;

  /** A buffer for forwarding instructions that should not be diverted to the
   * accelerator. */
  port passThroughOutput_;

  /** A buffer for writing instructions executed by the accelerator into. */
  port& offloadedOutput_;

  /** A function handle called when forwarding operands. */
  const forward_operands forwardOperands_;

  /** A function handle called upon exception generation. */
  const raise_exception raiseException_;

  /** A function handle that determines whether an instruction should be
   * diverted to an accelerator. A return value of true indicates that the
   * instruction should be sent to the accelerator. */
  instruction_filter filter_;

  void offload(std::shared_ptr<Instruction> uop);
};

}  // namespace pipeline
}  // namespace simeng