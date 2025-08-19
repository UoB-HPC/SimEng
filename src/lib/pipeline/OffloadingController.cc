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
    for (uint16_t slot = 0; slot < rename_.getWidth(); ++slot) {
      rename_.getTailSlots()[slot] = nullptr;
    }
    for (uint16_t slot = 0; slot < input_.getWidth(); ++slot) {
      auto uop = std::move(input_.getHeadSlots()[slot]);
      if (uop == nullptr || uop->isFlushed()) continue;

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
    auto received = gateway_.tickInbound();
    if (received.has_value()) {
      write_received(std::move(received.value()));
    }
  }
}

void OffloadingController::write_received(payload_t payload) {
  const auto id = payload.id_;
  switch (payload.type_) {
    case OffloadingPayload::Type::Schedule: {
      assert(false && "Accelerators cannot schedule instructions on the core");
    }
    case OffloadingPayload::Type::Commit: {
      assert(offloaded_.find(id) != offloaded_.end() &&
             "Cannot commit: unknown payload ID");

      auto uop = offloaded_[id];
      // TODO: What if flush request comes after commit?
      offloaded_.erase(id);
      assert(!uop->isFlushed() &&
             "Instructions that have been sent to an accelerator cannot be "
             "flushed in the meantime");

      // Update `uop` with data from the accelerator
      uop->moveOffloadedResults(payload.insn_);
      uop->setAcceleratorCommited();

      if (uop->exceptionEncountered()) {
        raiseException_(uop);
        return;
      }

      // Forward operands (only non-offloaded ones)
      std::vector<Register> coreRegs;
      std::vector<RegisterValue> coreVals;
      const auto regs = uop->getDestinationRegisters();
      const auto vals = uop->getResults();
      for (size_t i = 0; i < regs.size(); i++) {
        const auto reg = regs[i];
        const auto& val = vals[i];
        if (uop->isRegisterOffloaded(reg)) continue;

        coreRegs.push_back(reg);
        coreVals.push_back(val);
      }
      forwardOperands_({coreRegs.data(), coreRegs.size()},
                       {coreVals.data(), coreVals.size()});

      output_.getTailSlots()[0] = std::move(uop);
      break;
    }
    case OffloadingPayload::Type::Flush: {
      if (offloaded_.find(id) == offloaded_.end()) break;

      const auto& uop = offloaded_[id];
      if (!flush_.has_value() || id < flush_.value().causeId) {
        flush_ = {id, uop};
      }
      break;
    }
    case OffloadingPayload::Type::Flushed: {
      assert(false && "Accelerators cannot confirm flushes");
    }
  }
}

void OffloadingController::purgeFlushed() {
  // Confirm flush
  if (flush_.has_value()) {
    // TODO: Just enqueue instead of ticking the whole gateway
    gateway_.tickOutbound(payload_t::confirmFlush(flush_.value().causeId));
  }
  flush_.reset();

  // Purge offloaded_
  for (auto it = offloaded_.begin(); it != offloaded_.end();) {
    if (it->second->isFlushed() || !it->second->isSequenceIdValid()) {
      it = offloaded_.erase(it);
    } else {
      ++it;
    }
  }

  // Purge pending_
  std::deque<payload_t::id_t> newPending;
  for (const auto id : pending_) {
    if (offloaded_.find(id) != offloaded_.end()) {
      newPending.push_back(id);
    }
  }
  pending_.swap(newPending);
}

bool OffloadingController::shouldFlush() const { return flush_.has_value(); }

const std::shared_ptr<Instruction>& OffloadingController::getFlushInsn() const {
  assert(flush_.has_value() && "No instruction is being flushed");
  return flush_.value().flushAfter;
}

}  // namespace pipeline
}  // namespace simeng
