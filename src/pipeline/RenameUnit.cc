#include "RenameUnit.hh"

#include <algorithm>

namespace simeng {
namespace pipeline {

RenameUnit::RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
                       ReorderBuffer& rob, RegisterAliasTable& rat,
                       LoadStoreQueue& lsq, uint8_t registerTypes)
    : input_(fromDecode),
      output_(toDispatch),
      reorderBuffer_(rob),
      rat_(rat),
      lsq_(lsq),
      freeRegistersAvailable_(registerTypes) {}

void RenameUnit::tick() {
  if (output_.isStalled()) {
    input_.stall(true);
    return;
  }

  // Get the number of available physical registers
  for (size_t type = 0; type < freeRegistersAvailable_.size(); type++) {
    freeRegistersAvailable_[type] = rat_.freeRegistersAvailable(type);
  }

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }
    if (reorderBuffer_.getFreeSpace() == 0) {
      input_.stall(true);
      robStalls_++;
      break;
    }
    if (uop->exceptionEncountered()) {
      // Exception; place in ROB, mark as ready, and remove from pipeline
      reorderBuffer_.reserve(uop);
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }

    // If it's a memory op, make sure there's space in the respective queue
    bool isLoad = uop->isLoad();
    bool isStore = uop->isStore();
    if (isLoad) {
      if (lsq_.getLoadQueueSpace() == 0) {
        lqStalls_++;
        input_.stall(true);
        break;
      }
    } else if (isStore) {
      if (lsq_.getStoreQueueSpace() == 0) {
        sqStalls_++;
        input_.stall(true);
        break;
      }
    }

    auto& destinationRegisters = uop->getDestinationRegisters();
    // Count the number of each type of destination registers needed, and ensure
    // enough free registers exist to allocate them.
    for (const auto& reg : destinationRegisters) {
      if (freeRegistersAvailable_[reg.type] == 0) {
        // Not enough free registers available for this uop
        input_.stall(true);
        allocationStalls_++;
        return;
      }
      freeRegistersAvailable_[reg.type]--;
    }

    input_.stall(false);

    // Allocate source registers
    auto& sourceRegisters = uop->getOperandRegisters();
    for (size_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];
      if (!uop->isOperandReady(i)) {
        uop->renameSource(i, rat_.getMapping(reg));
      }
    }

    // Allocate destination registers
    for (size_t i = 0; i < destinationRegisters.size(); i++) {
      const auto& reg = destinationRegisters[i];
      uop->renameDestination(i, rat_.allocate(reg));
    }

    // Reserve a slot in the ROB for this uop
    reorderBuffer_.reserve(uop);

    // Add to the load/store queue if appropriate
    if (isLoad) {
      lsq_.addLoad(uop);
    } else if (isStore) {
      lsq_.addStore(uop);
    }

    output_.getTailSlots()[slot] = uop;
    input_.getHeadSlots()[slot] = nullptr;
  }
}

uint64_t RenameUnit::getAllocationStalls() const { return allocationStalls_; }
uint64_t RenameUnit::getROBStalls() const { return robStalls_; }

uint64_t RenameUnit::getLoadQueueStalls() const { return lqStalls_; }
uint64_t RenameUnit::getStoreQueueStalls() const { return sqStalls_; }

}  // namespace pipeline
}  // namespace simeng
