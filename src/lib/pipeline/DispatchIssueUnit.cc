#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <unordered_set>

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure,
    std::vector<std::pair<uint8_t, uint64_t>> rsArrangement)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      rsArrangement_(rsArrangement),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
  
  int num_RSs = 0;
  for (auto port : rsArrangement_) {
    num_RSs = std::max(num_RSs, port.first+1);
  }
  readyQueues_.resize(num_RSs);
  rsSize_ = std::vector<size_t>(num_RSs, 0);
};

void DispatchIssueUnit::tick() {
  input_.stall(false);
  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    uint8_t port = portAllocator_.allocate(uop->getGroup());
    uint8_t readyQueueIndex = rsArrangement_[port].first;
    assert(readyQueueIndex < readyQueues_.size() && "Allocated port inaccessible");
    if (rsSize_[readyQueueIndex] == rsArrangement_[port].second) {
      input_.stall(true);
      rsStalls_++;
      portAllocator_.deallocate(port);
      return;
    }
    input_.stall(false);

    // Assume the uop will be ready
    bool ready = true;

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

    // Set scoreboard for all destination registers as not ready
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      scoreboard_[reg.type][reg.tag] = false;
    }

    if (ready) {
      readyQueues_[readyQueueIndex].push_back({std::move(uop), port});
    }

    rsSize_[readyQueueIndex]++;

    input_.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::issue() {
  int issued = 0;
  // Check the ready queues, and issue an instruction from each if the
  // corresponding port isn't blocked
  for (size_t i = 0; i < issuePorts_.size(); i++) {
    uint8_t readyQueueIndex = rsArrangement_[i].first;
    auto& queue = readyQueues_[readyQueueIndex];
    // auto& queue = readyQueues_[i];
    if (issuePorts_[i].isStalled()) {
      if (queue.size() > 0) {
        portBusyStalls_++; 
      }
      continue;
    }

    if (queue.size() > 0) {
      // Locate first instruction in queue assigned to the port
      auto it = queue.begin();
      while (it != queue.end()) {
        auto port = (*it).second;
        if (i == port) {
          // Move instruction into port
          auto& uop = (*it).first;
          issuePorts_[i].getTailSlots()[0] = std::move(uop);
          it = queue.erase(it);

          // Inform the port allocator that an instruction issued
          portAllocator_.issued(port);
          issued++;

          assert(rsSize_[readyQueueIndex] > 0);
          rsSize_[readyQueueIndex]--;
          break;
        } else {
          it++;
        }
      }
    }
  }

  if (issued == 0) {
    bool empty = true;
    for(auto entry : rsSize_) {
      if(entry != 0) {
        empty = false;
        break;
      }
    }
    if (empty) {
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
        readyQueues_[rsArrangement_[entry.port].first].push_back({
          std::move(entry.uop), entry.port});
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
      auto& uop = (*it).first;
      if (uop->isFlushed()) {
        portAllocator_.deallocate((*it).second);
        it = queue.erase(it);
        assert(rsSize_[i] > 0);
        rsSize_[i]--;
      } else {
        it++;
      }
    }
  }

  // Collect flushed instructions and remove them from the dependency matrix
  std::vector<std::unordered_set<std::shared_ptr<Instruction>>> flushed(rsSize_.size(), 
    *(new std::unordered_set<std::shared_ptr<Instruction>>));
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      // Instructions are added in-order, so flushed instructions will be at the
      // back of each dependency list. Walk backwards through the list and add
      // the flushed instructions to the set.
      int i;
      for (i = dependencyList.size() - 1; i >= 0; i--) {
        auto& uop = dependencyList[i].uop;
        auto readyQueueIndex = rsArrangement_[dependencyList[i].port].first;
        if (!uop->isFlushed()) {
          // Stop at first (newest) non-flushed instruction
          break;
        }
        if (!flushed[readyQueueIndex].count(uop)) {
          flushed[readyQueueIndex].insert(uop);

          // Inform the allocator we've removed an instruction
          portAllocator_.deallocate(dependencyList[i].port);
        }
      }
      // Resize the dependency list to remove flushed instructions from it
      dependencyList.resize(i + 1);
    }
  }

  // Update reservation station size
  for(int i = 0; i < rsSize_.size(); i++) {
    assert(rsSize_[i] >= flushed[i].size());
    rsSize_[i] -= flushed[i].size();
  }
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
