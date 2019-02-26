#include "DispatchIssueUnit.hh"

namespace simeng {
namespace outoforder {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure,
    unsigned int maxReservationStationSize)
    : fromRenameBuffer(fromRename),
      issuePorts(issuePorts),
      registerFileSet(registerFileSet),
      scoreboard(physicalRegisterStructure.size()),
      maxReservationStationSize(maxReservationStationSize),
      dependencyMatrix(physicalRegisterStructure.size()),
      portAllocator(portAllocator) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix[type].resize(physicalRegisterStructure[type]);
  }
};

void DispatchIssueUnit::tick() {
  for (size_t slot = 0; slot < fromRenameBuffer.getWidth(); slot++) {
    auto& uop = fromRenameBuffer.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }
    if (reservationStation.size() == maxReservationStationSize) {
      fromRenameBuffer.stall(true);
      rsStalls++;
      return;
    }
    fromRenameBuffer.stall(false);

    // Assume the uop will be ready
    bool ready = true;

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getOperandRegisters();
    for (size_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];

      if (!uop->isOperandReady(i)) {
        // The operand hasn't already been supplied
        if (scoreboard[reg.type][reg.tag]) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(reg, registerFileSet.get(reg));
        } else {
          // This register isn't ready yet. Register this uop to the dependency
          // matrix for a more efficient lookup later
          dependencyMatrix[reg.type][reg.tag].push_back(uop);
          ready = false;
        }
      }
    }

    if (ready) {
      readyCount++;
    }

    // Set scoreboard for all destination registers as not ready
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      scoreboard[reg.type][reg.tag] = false;
    }

    reservationStation.push_back(uop);
    fromRenameBuffer.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::issue() {
  const int maxIssue = issuePorts.size();
  int issued = 0;
  auto it = reservationStation.begin();

  // Iterate over RS to find a ready uop to issue
  while (issued < maxIssue && it != reservationStation.end() &&
         readyCount > 0) {
    auto& entry = *it;

    if (entry->canExecute()) {
      // Found a suitable entry; add to output, increment issue counter,
      // decrement ready counter, and remove from RS
      issuePorts[issued].getTailSlots()[0] = entry;
      issued++;
      readyCount--;

      if (it != reservationStation.begin()) {
        outOfOrderIssues++;
      }
      it = reservationStation.erase(it);
    } else {
      it++;
    }
  }

  if (issued == 0) {
    if (reservationStation.size() == 0) {
      frontendStalls++;
    } else {
      backendStalls++;
    }
  }
}

void DispatchIssueUnit::forwardOperands(const span<Register>& registers,
                                        const span<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (size_t i = 0; i < registers.size(); i++) {
    const auto& reg = registers[i];
    // Flag scoreboard as ready now result is available
    scoreboard[reg.type][reg.tag] = true;

    // Supply the value to all dependent uops
    const auto& dependents = dependencyMatrix[reg.type][reg.tag];
    for (auto& uop : dependents) {
      uop->supplyOperand(reg, values[i]);
      if (uop->canExecute()) {
        readyCount++;
      }
    }

    // Clear the dependency list
    dependencyMatrix[reg.type][reg.tag].clear();
  }
}

void DispatchIssueUnit::setRegisterReady(Register reg) {
  scoreboard[reg.type][reg.tag] = true;
}

void DispatchIssueUnit::purgeFlushed() {
  auto it = reservationStation.begin();
  while (it != reservationStation.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      if (entry->canExecute()) {
        readyCount--;
      }
      it = reservationStation.erase(it);
    } else {
      it++;
    }
  }
}

uint64_t DispatchIssueUnit::getRSStalls() const { return rsStalls; }
uint64_t DispatchIssueUnit::getFrontendStalls() const { return frontendStalls; }
uint64_t DispatchIssueUnit::getBackendStalls() const { return backendStalls; }
uint64_t DispatchIssueUnit::getOutOfOrderIssueCount() const {
  return outOfOrderIssues;
}

}  // namespace outoforder
}  // namespace simeng
