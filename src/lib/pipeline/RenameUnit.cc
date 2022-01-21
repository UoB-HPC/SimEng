#include "simeng/pipeline/RenameUnit.hh"

#include <algorithm>
#include <iostream>

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

  input_.stall(false);

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
      return;
    }
    if (uop->exceptionEncountered()) {
      // Exception; place in ROB, mark as ready, and remove from pipeline
      reorderBuffer_.reserve(uop);
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      input_.stall(false);
      continue;
    }

    // If it's a memory op, make sure there's space in the respective queue
    bool isLoad = uop->isLoad();
    bool isStore = uop->isStoreAddress();
    if (isLoad) {
      if (lsq_.getLoadQueueSpace() == 0) {
        lqStalls_++;
        input_.stall(true);
        return;
      }
    } else if (isStore) {
      if (lsq_.getStoreQueueSpace() == 0) {
        sqStalls_++;
        input_.stall(true);
        return;
      }
    }

    bool serialize = false;

    auto& destinationRegisters = uop->getDestinationRegisters();
    // Count the number of each type of destination registers needed, and ensure
    // enough free registers exist to allocate them.
    for (const auto& reg : destinationRegisters) {
      // Check whether renaming is allowed, otherwise we need to serialize
      if (!rat_.canRename(reg.type)) {
        serialize = true;
        continue;
      }

      if (freeRegistersAvailable_[reg.type] == 0) {
        // Not enough free registers available for this uop
        input_.stall(true);
        allocationStalls_++;
        return;
      }
      freeRegistersAvailable_[reg.type]--;
    }

    if (serialize) {
      // Wait until ROB is empty before continuing
      if (reorderBuffer_.size() > 0) {
        input_.stall(true);
        return;
      }
    }

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
      if (rat_.canRename(reg.type)) {
        uop->renameDestination(i, rat_.allocate(reg));
      }
    }

    // Reserve a slot in the ROB for this uop
    reorderBuffer_.reserve(uop);

    // Add to the load/store queue if appropriate
    if (isLoad) {
      lsq_.addLoad(uop);
    }
    if (isStore) {
      lsq_.addStore(uop);
    }

    std::cout << "Rename: " << uop->getSequenceId() << ":"
              << uop->getInstructionId() << ":0x" << std::hex
              << uop->getInstructionAddress() << std::dec << ":"
              << uop->getMicroOpIndex() << std::endl;
    output_.getTailSlots()[slot] = std::move(uop);
  }
}

uint64_t RenameUnit::getAllocationStalls() const { return allocationStalls_; }
uint64_t RenameUnit::getROBStalls() const { return robStalls_; }

uint64_t RenameUnit::getLoadQueueStalls() const { return lqStalls_; }
uint64_t RenameUnit::getStoreQueueStalls() const { return sqStalls_; }

}  // namespace pipeline
}  // namespace simeng
