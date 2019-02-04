#include "DispatchIssueUnit.hh"

#include <iostream>

namespace simeng {
namespace outoforder {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
    const RegisterFile& registerFile,
    const std::vector<uint16_t>& physicalRegisterStructure)
    : fromRenameBuffer(fromRename),
      toExecuteBuffer(toExecute),
      registerFile(registerFile),
      scoreboard(physicalRegisterStructure.size()) {
  // Initialise scoreboard
  for (size_t i = 0; i < physicalRegisterStructure.size(); i++) {
    scoreboard[i].assign(physicalRegisterStructure[i], true);
  }
};

void DispatchIssueUnit::tick() {
  auto uop = fromRenameBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }

  // Register read
  // Identify remaining missing registers and supply values
  auto sourceRegisters = uop->getOperandRegisters();
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    auto reg = sourceRegisters[i];

    // If the operand hasn't already been supplied, and the scoreboard says it's
    // ready, read and supply the register value
    if (!uop->isOperandReady(i) && scoreboard[reg.type][reg.tag]) {
      uop->supplyOperand(reg, registerFile.get(reg));
    }
  }

  // Set scoreboard for all destination registers as not ready
  auto destinationRegisters = uop->getDestinationRegisters();
  for (const auto& reg : destinationRegisters) {
    scoreboard[reg.type][reg.tag] = false;
  }

  // Add to RS
  // reservationStation.push_back(uop);

  toExecuteBuffer.getTailSlots()[0] = uop;
  fromRenameBuffer.getHeadSlots()[0] = nullptr;
}

void DispatchIssueUnit::forwardOperands(
    const std::vector<Register>& registers,
    const std::vector<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  auto uop = toExecuteBuffer.getTailSlots()[0];
  if (uop == nullptr) {
    return;
  }
  if (uop->canExecute()) {
    return;
  }

  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    // Flag scoreboard as ready now result is available
    scoreboard[reg.type][reg.tag] = true;

    uop->supplyOperand(reg, values[i]);
  }
}

void DispatchIssueUnit::setRegisterReady(Register reg) {
  scoreboard[reg.type][reg.tag] = true;
}

}  // namespace outoforder
}  // namespace simeng
