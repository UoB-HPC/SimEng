#pragma once

#include <vector>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/noc/NocGateway.hh"

namespace simeng {
namespace pipeline {

/** A controller responsible for managing flow of instructions to an
 * accelerator. All instructions that should be offloaded are diverted and sent
 * over a NoC; all other instructions are forwarded to the pass-through port,
 * which can be connected to a regular Execute Unit. */
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
  /** Constructs an offloading controller with references to an input and output
   * buffer, handlers for forwarding operands and exceptions, and a filter for
   * deciding whether an instruction should be diverted to an accelerator. */
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
  /** A NoC packet data to be sent to the accelerator. */
  struct AcceleratorPacket {
    /** The instruction to execute. */
    std::shared_ptr<Instruction> insn_;

    /** Creates new packet data based on the provided instruction. */
    explicit AcceleratorPacket(const std::shared_ptr<Instruction>& insn);

    /** Updates the provided instruction's data based on the result data stored
     * in the packet. */
    void updateInstruction(std::shared_ptr<Instruction>& insn);
  };

  /** Sends the resolved uop back to the regular pipeline's output buffer, also
   * forwarding the results to dispatch/issue.  */
  void write_received(std::shared_ptr<Instruction> uop) const;

  /** A Network-on-Chip gateway for communicating with the accelerator. */
  noc::NocGateway<AcceleratorPacket, AcceleratorPacket> gateway_;

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

 // TODO: Add accelerator instance.
};

}  // namespace pipeline
}  // namespace simeng