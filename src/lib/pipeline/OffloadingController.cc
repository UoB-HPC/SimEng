#include "simeng/pipeline/OffloadingController.hh"

#include <iostream>
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
  if (uop == nullptr || uop->isFlushed()) return;

  if (filter_(uop)) {
    // Offloading to an accelerator
    offload(std::move(uop));
  } else {
    // Forwarding to the associated Execute Unit
    passThroughOutput_.getTailSlots()[0] = std::move(uop);
  }

  passThroughOutput_.tick();
}

void OffloadingController::offload(std::shared_ptr<Instruction> uop) {
  // TODO: Implement offloading circuitry
  assert(false && "Not implemented");
}

void OffloadingController::purgeFlushed() {
  // TODO: Implement flushing after the internal pipeline has been added
}

}  // namespace pipeline
}  // namespace simeng