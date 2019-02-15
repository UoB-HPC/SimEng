#include "RenameUnit.hh"

namespace simeng {
namespace outoforder {

RenameUnit::RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
                       ReorderBuffer& rob, RegisterAliasTable& rat)
    : fromDecodeBuffer(fromDecode),
      toDispatchBuffer(toDispatch),
      reorderBuffer(rob),
      rat(rat) {}

void RenameUnit::tick() {
  auto& uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }

  // Allocate source registers
  auto& sourceRegisters = uop->getOperandRegisters();
  std::vector<Register> renamedSources(sourceRegisters.size());
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    const auto& reg = sourceRegisters[i];
    if (!uop->isOperandReady(i)) {
      renamedSources[i] = rat.getMapping(reg);
    } else {
      renamedSources[i] = reg;
    }
  }

  // Allocate destination registers
  auto& destinationRegisters = uop->getDestinationRegisters();
  std::vector<Register> renamedDestinations(destinationRegisters.size());
  for (size_t i = 0; i < destinationRegisters.size(); i++) {
    const auto& reg = destinationRegisters[i];
    renamedDestinations[i] = rat.allocate(reg);
  }

  // Supply uop with renamed registers
  uop->rename(renamedDestinations, renamedSources);

  // Reserve a slot in the ROB for this uop
  reorderBuffer.reserve(uop);

  toDispatchBuffer.getTailSlots()[0] = uop;
  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}
}  // namespace outoforder
}  // namespace simeng
