#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <unordered_set>

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
      readyQueues_(issuePorts.size()) {
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
    if (rsSize_ == maxReservationStationSize_) {
      input_.stall(true);
      rsStalls_++;
      return;
    }
    input_.stall(false);

    // Assume the uop will be ready
    bool ready = true;

    uint8_t port = portAllocator_.allocate(uop->getGroup());
    assert(port < readyQueues_.size() && "Allocated port inaccessible");

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getOperandRegisters();
    for (uint8_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];

      if (!uop->isOperandReady(i)) {
        // The operand hasn't already been supplied
        if (scoreboard_[reg.type][reg.tag]) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(i, registerFileSet_.get(reg));
        } else {
          // This register isn't ready yet. Register this uop to the dependency
          // matrix for a more efficient lookup later
          dependencyMatrix_[reg.type][reg.tag].push_back({uop, port, i});
          ready = false;
        }
      }
    }

    if (ready) {
      readyQueues_[port].push_back(uop);
    }

    // Set scoreboard for all destination registers as not ready
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      scoreboard_[reg.type][reg.tag] = false;
    }

    rsSize_++;

    input_.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::issue() {
  int issued = 0;
  // Check the ready queues, and issue an instruction from each if the
  // corresponding port isn't blocked
  for (size_t i = 0; i < issuePorts_.size(); i++) {
    if (issuePorts_[i].isStalled()) {
      if (readyQueues_[i].size() > 0) {
        portBusyStalls_++;
      }
      continue;
    }

    if (readyQueues_[i].size() > 0) {
      // Assign the instruction to the port
      auto& uop = readyQueues_[i].front();
      issuePorts_[i].getTailSlots()[0] = uop;
      readyQueues_[i].pop_front();

      // Inform the port allocator that an instruction issued
      portAllocator_.issued(i);
      issued++;

      assert(rsSize_ > 0);
      rsSize_--;
    }
  }

  if (issued == 0) {
    if (rsSize_ == 0) {
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
    for (auto& entry : dependents) {
      entry.uop->supplyOperand(entry.operandIndex, values[i]);
      if (entry.uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        readyQueues_[entry.port].push_back(entry.uop);
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
  for (size_t i = 0; i < readyQueues_.size(); i++) {
    // Search the ready queues for flushed instructions and remove them
    auto& queue = readyQueues_[i];
    auto it = queue.begin();
    while (it != queue.end()) {
      auto& uop = *it;
      if (uop->isFlushed()) {
        it = queue.erase(it);
        assert(rsSize_ > 0);
        rsSize_--;
      } else {
        it++;
      }
    }
  }

  // Collect flushed instructions and remove them from the dependency matrix
  std::unordered_set<std::shared_ptr<Instruction>> flushed;
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      // Instructions are added in-order, so flushed instructions will be at the
      // back of each dependency list. Walk backwards through the list and add
      // the flushed instructions to the set.
      int i;
      for (i = dependencyList.size() - 1; i >= 0; i--) {
        auto& uop = dependencyList[i].uop;
        if (!uop->isFlushed()) {
          // Stop at first (newest) non-flushed instruction
          break;
        }
        if (!flushed.count(uop)) {
          flushed.insert(uop);

          // Inform the allocator we've removed an instruction
          portAllocator_.deallocate(dependencyList[i].port);
        }
      }
      // Resize the dependency list to remove flushed instructions from it
      dependencyList.resize(i + 1);
    }
  }

  // Update reservation station size
  assert(rsSize_ >= flushed.size());
  rsSize_ -= flushed.size();
}

uint64_t DispatchIssueUnit::getRSStalls() const { return rsStalls_; }
uint64_t DispatchIssueUnit::getFrontendStalls() const {
  return frontendStalls_;
}
uint64_t DispatchIssueUnit::getBackendStalls() const { return backendStalls_; }
uint64_t DispatchIssueUnit::getPortBusyStalls() const {
  return portBusyStalls_;
}

}  // namespace pipeline
}  // namespace simeng
