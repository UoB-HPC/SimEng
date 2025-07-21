#include "simeng/pipeline/OffloadingController.hh"

#include <utility>

namespace simeng {
namespace pipeline {

OffloadingController::OffloadingController(port& input, port& output,
                                           forward_operands forwardOperands,
                                           raise_exception raiseException)
    : gateway_(config::SimInfo::getOffloadingLogic().send_,
               config::SimInfo::getOffloadingLogic().receive_),
      input_(input),
      passThroughOutput_(std::make_shared<port>(1, nullptr)),
      offloadedOutput_(output),
      forwardOperands_(std::move(forwardOperands)),
      raiseException_(std::move(raiseException)),
      filter_(config::SimInfo::getOffloadingLogic().filter_) {}

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