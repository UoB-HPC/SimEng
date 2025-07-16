#include "simeng/pipeline/OffloadingController.hh"

#include <utility>

namespace simeng {
namespace pipeline {

OffloadingController::OffloadingController(port& input, port& output,
                                           forward_operands forwardOperands,
                                           raise_exception raiseException,
                                           instruction_filter filter,
                                           connection_t* out_,
                                           connection_t* in_)
    : gateway_(
          // TODO: Refactor when moving to SST
          [out_](const auto& packet) {
            if (out_->has_value()) return false;
            *out_ = packet;
            return true;
          },
          [in_] {
            auto packet = *in_;
            in_->reset();
            return packet;
          }),
      input_(input),
      passThroughOutput_(std::make_shared<port>(1, nullptr)),
      offloadedOutput_(output),
      forwardOperands_(std::move(forwardOperands)),
      raiseException_(std::move(raiseException)),
      filter_(std::move(filter)),
      accelerator_(
          // TODO: Refactor when moving to SST
          [in_](const auto& packet) {
            if (in_->has_value()) return false;
            *in_ = packet;
            return true;
          },
          [out_] {
            auto packet = *out_;
            out_->reset();
            return packet;
          },
          true, {}) {}

OffloadingController::port& OffloadingController::getPassThroughPort()
    const noexcept {
  return *passThroughOutput_;
}

void OffloadingController::tick() {
  auto uop = std::move(input_.getHeadSlots()[0]);
  std::optional<std::shared_ptr<Instruction>> outbound = {};
  if (uop != nullptr && !uop->isFlushed()) {
    if (filter_(uop)) {
      // Offloading to an accelerator
      outbound = uop;
    } else {
      // Forwarding to the associated Execute Unit
      passThroughOutput_->getTailSlots()[0] = uop;
    }
  }

  // TODO: What if the gateway is stalling?
  gateway_.tickOutbound(std::move(outbound));
  accelerator_.tick();
  auto received = gateway_.tickInbound();
  if (received.has_value()) {
    write_received(std::move(received.value()));
  }

  passThroughOutput_->tick();
}

void OffloadingController::write_received(
    std::shared_ptr<Instruction> uop) const {
  if (uop == nullptr || uop->isFlushed()) return;

  if (uop->exceptionEncountered()) {
    raiseException_(uop);
    return;
  }

  // TODO: Branch misprediction (see ExecuteUnit.cc:140)

  forwardOperands_(uop->getDestinationRegisters(), uop->getResults());
  offloadedOutput_.getTailSlots()[0] = std::move(uop);
}

void OffloadingController::purgeFlushed() {}

}  // namespace pipeline
}  // namespace simeng