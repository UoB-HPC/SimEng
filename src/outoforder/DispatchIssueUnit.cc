#include "DispatchIssueUnit.hh"

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
  auto& uop = fromRenameBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }

  // Register read
  // Identify remaining missing registers and supply values
  auto& sourceRegisters = uop->getOperandRegisters();
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    const auto& reg = sourceRegisters[i];

    // If the operand hasn't already been supplied, and the scoreboard says it's
    // ready, read and supply the register value
    if (!uop->isOperandReady(i) && scoreboard[reg.type][reg.tag]) {
      uop->supplyOperand(reg, registerFile.get(reg));
    }
  }

  // Set scoreboard for all destination registers as not ready
  auto& destinationRegisters = uop->getDestinationRegisters();
  for (const auto& reg : destinationRegisters) {
    scoreboard[reg.type][reg.tag] = false;
  }

  reservationStation.push_back(uop);
  fromRenameBuffer.getHeadSlots()[0] = nullptr;
}

void DispatchIssueUnit::issue() {
  // Iterate over RS to find a ready uop to issue

  const int maxIssue = 1;
  int issued = 0;
  auto it = reservationStation.begin();
  while (it != reservationStation.end() && issued < maxIssue) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      it = reservationStation.erase(it);
      continue;
    }

    if (entry->canExecute()) {
      toExecuteBuffer.getTailSlots()[0] = entry;
      issued++;
      it = reservationStation.erase(it);
    } else {
      it++;
    }
  }
}

void DispatchIssueUnit::forwardOperands(
    const std::vector<Register>& registers,
    const std::vector<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (const auto& reg : registers) {
    // Flag scoreboard as ready now result is available
    scoreboard[reg.type][reg.tag] = true;
  }

  // TODO: Replace with dependency matrix
  for (auto& uop : reservationStation) {
    if (uop == nullptr) {
      return;
    }
    if (uop->canExecute()) {
      return;
    }

    const auto& sourceRegisters = uop->getOperandRegisters();
    for (size_t i = 0; i < registers.size(); i++) {
      for (size_t j = 0; j < sourceRegisters.size(); j++) {
        const auto& reg = registers[i];

        if (sourceRegisters[j] == reg && !uop->isOperandReady(j)) {
          uop->supplyOperand(reg, values[i]);
        }
      }
    }
  }
}

void DispatchIssueUnit::setRegisterReady(Register reg) {
  scoreboard[reg.type][reg.tag] = true;
}

}  // namespace outoforder
}  // namespace simeng
