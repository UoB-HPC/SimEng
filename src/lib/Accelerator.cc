#include "simeng/Accelerator.hh"

namespace simeng {

AcceleratorPacket::AcceleratorPacket(const std::shared_ptr<Instruction>& insn)
    : insn_(insn) {}

std::shared_ptr<Instruction> AcceleratorPacket::into() {
  return std::move(insn_);
}

Accelerator::Accelerator(const id_t id, gateway_t::send_fn_t send_fn,
                         gateway_t::receive_fn_t receive_fn)
    : input_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      output_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      gateway_(std::move(send_fn), std::move(receive_fn)),
      id_(id) {}

void Accelerator::tick() {
  if (input_->getTailSlots()[0] == nullptr) {
    // The accelerator is not stalling the in-bound queue
    input_->getTailSlots()[0] =
        std::move(gateway_.tickInbound().value_or(nullptr));

    // TODO: Tick the gateway even if stalling
    //       (maybe part the gateway's internal pipeline can tick?)
  }

  // TODO: What if the gateway needs to stall?
  std::optional<std::shared_ptr<Instruction>> outbound = {};
  auto output = std::move(output_->getHeadSlots()[0]);
  if (output != nullptr) {
    outbound = std::move(output);
  }
  gateway_.tickOutbound(std::move(outbound));

  tickImpl();

  input_->tick();
  output_->tick();
}

Accelerator::id_t Accelerator::getId() const noexcept { return id_; }

}  // namespace simeng