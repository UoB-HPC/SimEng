#pragma once

#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/noc/NocGateway.hh"

namespace simeng {

/** A NoC packet data to be sent to the accelerator. */
struct AcceleratorPacket {
  /** The instruction to execute on the accelerator. */
  std::shared_ptr<Instruction> insn_;

  /** Creates new packet based on the provided instruction. */
  explicit AcceleratorPacket(const std::shared_ptr<Instruction>& insn);

  /** Extracts the instruction from the packet. */
  std::shared_ptr<Instruction> into();
};

class Accelerator {
  using pipeline_buffer_t =
      pipeline::PipelineBuffer<std::shared_ptr<Instruction>>;

  using gateway_t = pipeline::noc::NocGateway<std::shared_ptr<Instruction>,
                                              AcceleratorPacket>;

 public:
  /** A unique identifier of an accelerator instance.
   * The value of 0 indicates the core (i.e. no accelerator). */
  using id_t = uint16_t;

  /** An ID signifying no accelerator
   * (see `simeng::config::OffloadingLogic::instruction_filter`). */
  constexpr static id_t NO_ACCELERATOR = 0;

  using send_fn_t = gateway_t::send_fn_t;
  using receive_fn_t = gateway_t::receive_fn_t;

  Accelerator(id_t id, send_fn_t send_fn, receive_fn_t receive_fn);

  virtual ~Accelerator() = default;

  /** Tick the accelerator. Propagates instructions through the internal
   * pipeline, including communication over the NoC. */
  void tick();

  /** Returns the unique identifier of this accelerator instance. */
  id_t getId() const noexcept;

 protected:
  //  TODO: Add a note mentioning the need for stalling if `output_` has a
  //        value (i.e. the NoC gateway is stalling)
  /** The concrete ticking logic for a given accelerator. An implementation
   * of this method should use `input_` to retrieve the latest instruction
   * supplied by the NoC, and `output_` to supply the results of an executed
   * instruction back to the NoC. */
  virtual void tickImpl() = 0;

  /** A pipeline buffer holding the latest instruction fetched from the NoC. */
  std::shared_ptr<pipeline_buffer_t> input_;

  /** A pipeline buffer holding the latest instruction executed by the
   * accelerator, waiting to be sent over the NoC. */
  std::shared_ptr<pipeline_buffer_t> output_;

 private:
  /** A Network-on-Chip gateway for communicating with the Core. */
  gateway_t gateway_;

  /** The unique identifier of this accelerator instance. */
  id_t id_;
};

}  // namespace simeng
