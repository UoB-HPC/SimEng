#include "RenameUnit.hh"

#include <algorithm>

namespace simeng {
namespace outoforder {

RenameUnit::RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
                       ReorderBuffer& rob, RegisterAliasTable& rat,
                       uint8_t registerTypes)
    : fromDecodeBuffer(fromDecode),
      toDispatchBuffer(toDispatch),
      reorderBuffer(rob),
      rat(rat),
      freeRegistersNeeded(registerTypes, 0) {}

void RenameUnit::tick() {
  if (toDispatchBuffer.isStalled()) {
    fromDecodeBuffer.stall(true);
    return;
  }

  auto& uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }
  if (reorderBuffer.getFreeSpace() == 0) {
    fromDecodeBuffer.stall(true);
    robStalls++;
    return;
  }

  auto& destinationRegisters = uop->getDestinationRegisters();
  // Count the number of each type of destination registers needed, and ensure
  // enough free registers exist to allocate them.
  std::fill(freeRegistersNeeded.begin(), freeRegistersNeeded.end(), 0);
  for (const auto& reg : destinationRegisters) {
    freeRegistersNeeded[reg.type]++;
  }
  for (size_t type = 0; type < freeRegistersNeeded.size(); type++) {
    if (freeRegistersNeeded[type] != 0) {
      if (!rat.canAllocate(type, freeRegistersNeeded[type])) {
        fromDecodeBuffer.stall(true);
        allocationStalls++;
        return;
      }
    }
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

  toDispatchBuffer.getTailSlots()[0] = uop;
  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}

uint64_t RenameUnit::getAllocationStalls() const { return allocationStalls; }
uint64_t RenameUnit::getROBStalls() const { return robStalls; }

}  // namespace outoforder
}  // namespace simeng
