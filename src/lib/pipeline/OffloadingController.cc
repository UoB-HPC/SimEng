#include "simeng/pipeline/OffloadingController.hh"

#include <utility>

#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace pipeline {

OffloadingController::OffloadingController(port& input, port& rename,
                                           port& output,
                                           forward_operands forwardOperands,
                                           raise_exception raiseException)
    : gateway_(config::SimInfo::getOffloadingLogic().send_,
               config::SimInfo::getOffloadingLogic().receive_),
      input_(input),
      rename_(rename),
      output_(output),
      forwardOperands_(std::move(forwardOperands)),
      raiseException_(std::move(raiseException)),
      filter_(config::SimInfo::getOffloadingLogic().filter_) {}

void OffloadingController::tick() {
  if (rename_.isStalled()) {
    input_.stall(true);
  } else {
    input_.stall(false);
    for (uint16_t slot = 0; slot < input_.getWidth(); ++slot) {
      auto uop = std::move(input_.getHeadSlots()[slot]);
      if (uop == nullptr || uop->isFlushed()) continue;

      // Cannot speculate if there are offloaded instructions
      if (uop->isBranch() && !offloaded_.empty()) {
        input_.getHeadSlots()[slot] = std::move(uop);
        input_.stall(true);
        break;
      }

      const auto acc_id = filter_(*uop);
      if (acc_id != Accelerator::NO_ACCELERATOR) {
        uop->markOffloaded(acc_id);
        // Instruction should be offloaded
        const auto id = nextId_++;
        pending_.push_back(id);
        offloaded_.emplace(id, uop);
      }

      rename_.getTailSlots()[slot] = uop;
    }
  }

  // Pass the oldest instruction to the gateway
  std::optional<payload_t> outbound = {};
  if (!pending_.empty()) {
    const auto id = pending_.front();
    const auto& insn = offloaded_[id];
    if (insn->canBeOffloaded()) {
      // TODO: What if the gateway is stalling?
      outbound = payload_t::schedule(id, insn->clone());
      pending_.pop_front();
    }
  }
  gateway_.tickOutbound(std::move(outbound));
  if (!output_.isStalled()) {
    const auto received = gateway_.tickInbound();
    if (received.has_value()) {
      write_received(received.value());
    }
  }
}

void OffloadingController::write_received(const payload_t& payload) {
  const auto& [id, type, seq, result] = payload;
  const auto uop = offloaded_[id];
  offloaded_.erase(id);
  if (uop == nullptr || uop->isFlushed()) return;

  if (uop->exceptionEncountered()) {
    // raiseException_(uop);
    return;
  }

  // TODO: Branch misprediction (see ExecuteUnit.cc:140)

  uop->setCommitReady();
}

void OffloadingController::purgeFlushed() {
  while (!pending_.empty()) {
    const auto id = pending_.back();
    const auto& insn = offloaded_[id];

    const auto isFlushed =
        (insn->isFlushed() && !insn->exceptionEncountered()) ||
        insn->getSequenceId() == 0;
    if (!isFlushed) break;

    offloaded_.erase(id);
    pending_.pop_back();
  }
}

}  // namespace pipeline
}  // namespace simeng
