#pragma once

#include <vector>

#include "simeng/Instruction.hh"
#include "simeng/config/OffloadingLogic.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/models/accelerator/SmeAccelerator.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/noc/OffloadingPayload.hh"

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

  using logic_t = config::OffloadingLogic;
  using payload_t = noc::OffloadingPayload;

 public:
  /** Constructs an offloading controller with references to an input and output
   * buffer, handlers for forwarding operands and exceptions, and a filter for
   * deciding whether an instruction should be diverted to an accelerator. */
  OffloadingController(port& input, port& rename, port& output,
                       forward_operands forwardOperands,
                       raise_exception raiseException);

  /** Tick the controller. Inspects incoming instructions and sends the
   * specialized ones to the accelerator. */
  void tick();

  /** Purge flushed instructions from the internal pipeline. */
  void purgeFlushed();

  /** Query whether an accelerator requested a flush in the most recent
   * cycle. */
  bool shouldFlush() const;

  /** Retrieve the instruction associated with the most recently requested
   * flush. */
  const std::shared_ptr<Instruction>& getFlushInsn() const;

 private:
  /** Sends the resolved uop back to the regular pipeline's output buffer, also
   * forwarding the results to dispatch/issue. */
  void write_received(payload_t payload);

  /** A Network-on-Chip gateway for communicating with the accelerator. */
  logic_t::gateway_t gateway_;

  /** A buffer of instructions to inspect. */
  port& input_;

  /** A buffer for writing inspected uops into. */
  port& rename_;

  /** A buffer for writing uops executed by an accelerator into. */
  port& output_;

  /** A function handle called when forwarding operands. */
  const forward_operands forwardOperands_;

  /** A function handle called upon exception generation. */
  const raise_exception raiseException_;

  /** A function handle that determines whether an instruction should be
   * diverted to an accelerator. A return value of true indicates that the
   * instruction should be sent to the accelerator. */
  logic_t::instruction_filter filter_;

  /** The next ID for an outbound payload. */
  payload_t::id_t nextId_ = 0;

  /** A queue for outbound instructions. */
  std::deque<payload_t::id_t> pending_;

  /** A registry of currently offloaded instructions. */
  std::unordered_map<payload_t::id_t, std::shared_ptr<Instruction>> offloaded_;

  /** Information about flushes triggered by accelerators. */
  struct FlushInfo {
    /** The payload ID of the causing the flush. */
    payload_t::id_t causeId;
    /** The instruction causing the flush. */
    std::shared_ptr<Instruction> flushAfter;
  };

  /** Information about the last flush triggered by an accelerator. */
  std::optional<FlushInfo> flush_ = std::nullopt;
};

}  // namespace pipeline
}  // namespace simeng