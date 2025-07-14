#include "simeng/pipeline/OffloadingController.hh"

#include <utility>

namespace simeng {
namespace pipeline {

OffloadingController::OffloadingController(port& input, port& output,
                                           forward_operands forwardOperands,
                                           raise_exception raiseException,
                                           instruction_filter filter)
    : input_(input),
      passThroughOutput_(1, nullptr),
      offloadedOutput_(output),
      forwardOperands_(std::move(forwardOperands)),
      raiseException_(std::move(raiseException)),
      filter_(std::move(filter)) {}

OffloadingController::port&
OffloadingController::getPassThroughPort() noexcept {
  return passThroughOutput_;
}

void OffloadingController::tick() {
  auto uop = std::move(input_.getHeadSlots()[0]);
  std::optional<std::shared_ptr<Instruction>> received;
  if (uop != nullptr && !uop->isFlushed()) {
    if (filter_(uop)) {
      // Offloading to an accelerator
      received = gateway_.tick(std::move(uop));
    } else {
      // Forwarding to the associated Execute Unit
      passThroughOutput_.getTailSlots()[0] = std::move(uop);
      received = gateway_.tick({});
    }
  } else {
    received = gateway_.tick({});
  }

  passThroughOutput_.tick();
  if (received.has_value()) {
    write_received(std::move(received.value()));
  }
}

void OffloadingController::write_received(
    std::shared_ptr<Instruction> uop) const {
  if (uop->exceptionEncountered()) {
    raiseException_(uop);
    return;
  }

  // TODO: Branch misprediction (see ExecuteUnit.cc:140)

  forwardOperands_(uop->getDestinationRegisters(), uop->getResults());
  offloadedOutput_.getTailSlots()[0] = std::move(uop);
}

void OffloadingController::purgeFlushed() { gateway_.purgeFlushed(); }

OffloadingController::AcceleratorPacket::AcceleratorPacket(
    const std::shared_ptr<Instruction>& insn)
    : insn_(insn) {}

void OffloadingController::AcceleratorPacket::updateInstruction(
    std::shared_ptr<Instruction>& insn) {
  insn.swap(insn_);
}

}  // namespace pipeline
}  // namespace simeng