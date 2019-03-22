#include "RenameUnit.hh"

#include <algorithm>

namespace simeng {
namespace outoforder {

RenameUnit::RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
                       ReorderBuffer& rob, RegisterAliasTable& rat,
                       LoadStoreQueue& lsq, uint8_t registerTypes)
    : fromDecodeBuffer(fromDecode),
      toDispatchBuffer(toDispatch),
      reorderBuffer(rob),
      rat(rat),
      lsq(lsq),
      freeRegistersAvailable(registerTypes) {}

void RenameUnit::tick() {
  if (toDispatchBuffer.isStalled()) {
    fromDecodeBuffer.stall(true);
    return;
  }

  // Get the number of available physical registers
  for (size_t type = 0; type < freeRegistersAvailable.size(); type++) {
    freeRegistersAvailable[type] = rat.freeRegistersAvailable(type);
  }

  for (size_t slot = 0; slot < fromDecodeBuffer.getWidth(); slot++) {
    auto& uop = fromDecodeBuffer.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }
    if (reorderBuffer.getFreeSpace() == 0) {
      fromDecodeBuffer.stall(true);
      robStalls++;
      break;
    }
    if (uop->exceptionEncountered()) {
      // Exception; place in ROB, mark as ready, and remove from pipeline
      reorderBuffer.reserve(uop);
      uop->setCommitReady();
      fromDecodeBuffer.getHeadSlots()[slot] = nullptr;
      continue;
    }

    // If it's a memory op, make sure there's space in the respective queue
    bool isLoad = uop->isLoad();
    bool isStore = uop->isStore();
    if (isLoad) {
      if (lsq.getLoadQueueSpace() == 0) {
        lqStalls++;
        fromDecodeBuffer.stall(true);
        break;
      }
    } else if (isStore) {
      if (lsq.getStoreQueueSpace() == 0) {
        sqStalls++;
        fromDecodeBuffer.stall(true);
        break;
      }
    }

    auto& destinationRegisters = uop->getDestinationRegisters();
    // Count the number of each type of destination registers needed, and ensure
    // enough free registers exist to allocate them.
    for (const auto& reg : destinationRegisters) {
      if (freeRegistersAvailable[reg.type] == 0) {
        // Not enough free registers available for this uop
        fromDecodeBuffer.stall(true);
        allocationStalls++;
        return;
      }
      freeRegistersAvailable[reg.type]--;
    }

    fromDecodeBuffer.stall(false);

    // Allocate source registers
    auto& sourceRegisters = uop->getOperandRegisters();
    for (size_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];
      if (!uop->isOperandReady(i)) {
        uop->renameSource(i, rat.getMapping(reg));
      }
    }

    // Allocate destination registers
    for (size_t i = 0; i < destinationRegisters.size(); i++) {
      const auto& reg = destinationRegisters[i];
      uop->renameDestination(i, rat.allocate(reg));
    }

    // Reserve a slot in the ROB for this uop
    reorderBuffer.reserve(uop);

    // Add to the load/store queue if appropriate
    if (isLoad) {
      lsq.addLoad(uop);
    } else if (isStore) {
      lsq.addStore(uop);
    }

    toDispatchBuffer.getTailSlots()[slot] = uop;
    fromDecodeBuffer.getHeadSlots()[slot] = nullptr;
  }
}

uint64_t RenameUnit::getAllocationStalls() const { return allocationStalls; }
uint64_t RenameUnit::getROBStalls() const { return robStalls; }

uint64_t RenameUnit::getLoadQueueStalls() const { return lqStalls; }
uint64_t RenameUnit::getStoreQueueStalls() const { return sqStalls; }

}  // namespace outoforder
}  // namespace simeng
