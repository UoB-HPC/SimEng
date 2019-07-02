#include "DispatchIssueUnit.hh"

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure,
    unsigned int maxReservationStationSize)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      maxReservationStationSize_(maxReservationStationSize),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator),
      availablePorts_(issuePorts.size()) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
};

void DispatchIssueUnit::tick() {
  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }
    if (reservationStation_.size() == maxReservationStationSize_) {
      input_.stall(true);
      rsStalls_++;
      return;
    }
    input_.stall(false);

    // Assume the uop will be ready
    bool ready = true;

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getOperandRegisters();
    for (size_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];

      if (!uop->isOperandReady(i)) {
        // The operand hasn't already been supplied
        if (scoreboard_[reg.type][reg.tag]) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(reg, registerFileSet_.get(reg));
        } else {
          // This register isn't ready yet. Register this uop to the dependency
          // matrix for a more efficient lookup later
          dependencyMatrix_[reg.type][reg.tag].push_back(uop);
          ready = false;
        }
      }
    }

    if (ready) {
      readyCount_++;
    }

    // Set scoreboard for all destination registers as not ready
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      scoreboard_[reg.type][reg.tag] = false;
    }

    uint8_t port = portAllocator_.allocate(uop->getGroup());

    reservationStation_.push_back({uop, port});
    input_.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::issue() {
  // Mark all ports as available unless they're stalled
  for (size_t i = 0; i < availablePorts_.size(); i++) {
    availablePorts_[i] = !issuePorts_[i].isStalled();
  }

  const int maxIssue = issuePorts_.size();
  int issued = 0;
  auto it = reservationStation_.begin();

  unsigned int readyRemaining = readyCount_;

  // Iterate over RS to find a ready uop to issue
  while (issued < maxIssue && it != reservationStation_.end() &&
         readyRemaining > 0) {
    auto& entry = *it;

    if (entry.uop->canExecute()) {
      if (!availablePorts_[entry.port]) {
        // Entry is ready, but port isn't available; skip
        readyRemaining--;
        portBusyStalls_++;
        continue;
      }

      // Found a suitable entry; add to output, increment issue counter,
      // decrement ready counter, and remove from RS
      issuePorts_[entry.port].getTailSlots()[0] = entry.uop;
      availablePorts_[entry.port] = false;
      portAllocator_.issued(entry.port);

      issued++;
      readyCount_--;
      readyRemaining--;

      if (it != reservationStation_.begin()) {
        outOfOrderIssues_++;
      }
      it = reservationStation_.erase(it);
    } else {
      it++;
    }
  }

  if (issued == 0) {
    if (reservationStation_.size() == 0) {
      frontendStalls_++;
    } else {
      backendStalls_++;
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
    scoreboard_[reg.type][reg.tag] = true;

    // Supply the value to all dependent uops
    const auto& dependents = dependencyMatrix_[reg.type][reg.tag];
    for (auto& uop : dependents) {
      uop->supplyOperand(reg, values[i]);
      if (uop->canExecute()) {
        readyCount_++;
      }
    }

    // Clear the dependency list
    dependencyMatrix_[reg.type][reg.tag].clear();
  }
}

void DispatchIssueUnit::setRegisterReady(Register reg) {
  scoreboard_[reg.type][reg.tag] = true;
}

void DispatchIssueUnit::purgeFlushed() {
  auto it = reservationStation_.begin();
  while (it != reservationStation_.end()) {
    auto& entry = *it;
    if (entry.uop->isFlushed()) {
      if (entry.uop->canExecute()) {
        readyCount_--;
      }
      portAllocator_.deallocate(entry.port);
      it = reservationStation_.erase(it);
    } else {
      it++;
    }
  }
}

uint64_t DispatchIssueUnit::getRSStalls() const { return rsStalls_; }
uint64_t DispatchIssueUnit::getFrontendStalls() const {
  return frontendStalls_;
}
uint64_t DispatchIssueUnit::getBackendStalls() const { return backendStalls_; }
uint64_t DispatchIssueUnit::getOutOfOrderIssueCount() const {
  return outOfOrderIssues_;
}
uint64_t DispatchIssueUnit::getPortBusyStalls() const {
  return portBusyStalls_;
}

}  // namespace pipeline
}  // namespace simeng
