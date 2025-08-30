#pragma once

#include "simeng/config/AcceleratorInfo.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/noc/NocGateway.hh"
#include "simeng/pipeline/noc/OffloadingPayload.hh"

namespace simeng {

using namespace pipeline::noc;

/** A NoC packet data to be sent to the accelerator. */
struct AcceleratorPacket {
  /** The payload to send to the accelerator. */
  OffloadingPayload payload_;

  /** Creates new packet containing the provided payload. */
  explicit AcceleratorPacket(OffloadingPayload payload);

  /** Extracts the payload from the packet. */
  OffloadingPayload into();
};

class Accelerator {
  using payload_t = OffloadingPayload;
  using pipeline_buffer_t =
      pipeline::PipelineBuffer<std::shared_ptr<Instruction>>;

 public:
  /** A unique identifier of an accelerator instance.
   * The value of 0 indicates the core (i.e. no accelerator). */
  using id_t = Instruction::accelerator_id_t;

  /** The type of the NoC gateway used offloading instructions. */
  using gateway_t = NocGateway<payload_t, AcceleratorPacket>;

  /** An ID signifying no accelerator
   * (see `simeng::config::OffloadingLogic::instruction_filter`). */
  constexpr static id_t NO_ACCELERATOR = Instruction::NO_ACCELERATOR;

  Accelerator(std::shared_ptr<config::AcceleratorInfo> info,
              gateway_t::send_fn_t send_fn, gateway_t::receive_fn_t receive_fn);

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

  /** Transform incoming instructions as specified by the concrete accelerator.
   * By default, does nothing. */
  virtual void mapIncoming(std::shared_ptr<Instruction>& insn);

  /** Transform outgoing instructions as specified by the concrete accelerator.
   * By default, does nothing. */
  virtual void mapOutgoing(std::shared_ptr<Instruction>& insn);

  /** Clears all instructions coming after the provided instruction. */
  void flush(const std::shared_ptr<Instruction>& flushAfter);

  /** An object holding configuration of the simulated accelerator. */
  std::shared_ptr<config::AcceleratorInfo> info_;

  /** A pipeline buffer holding the latest instruction fetched from the NoC. */
  std::shared_ptr<pipeline_buffer_t> input_;

  /** A pipeline buffer holding the latest instruction executed by the
   * accelerator, waiting to be sent over the NoC. */
  std::shared_ptr<pipeline_buffer_t> output_;

 private:
  /** A Network-on-Chip gateway for communicating with the Core. */
  gateway_t gateway_;

  /** A map from in-flight instructions to original payload and sequence IDs
   * on the core. */
  std::unordered_map<const Instruction*, std::pair<payload_t::id_t, uint64_t>>
      insnMeta_;

  /** The payload ID of the instruction currently being flushed. */
  std::optional<payload_t::id_t> flushing_;
};

}  // namespace simeng
