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
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
  
  for (int port = 0; port < rsArrangement.size(); port++) {
    auto RS = rsArrangement[port];
    // Allocate RS port resources
    if (readyQueues_.size() < RS.first + 1) {
      readyQueues_.resize(RS.first + 1);
      stallQueues_.resize(RS.first + 1);
      maxReservationStationSize_.resize(RS.first + 1);
    }
    maxReservationStationSize_[RS.first] = RS.second;
    // Find number of ports already mapping to the given RS
    uint8_t port_index = 0;
    for (auto rsPort : portMapping_){
      if (rsPort.first == RS.first) { port_index++; }
    }
    // Set mapping from port to RS port
    portMapping_.push_back({RS.first, port_index});
    readyQueues_[RS.first].push_back({port, *(new std::deque<std::shared_ptr<Instruction>>)});
    stallQueues_[RS.first].push_back({port, *(new std::deque<std::shared_ptr<Instruction>>)});
  }
  rsSize_ = std::vector<size_t>(readyQueues_.size(), 0);
};

void DispatchIssueUnit::tick() {

  // Unstall instructions whose RS has free space
  for (auto& RS : stallQueues_) {
    for (auto& port : RS) {
      uint8_t RS_Index = portMapping_[port.first].first;
      auto& queue = port.second;
      for (size_t entry = 0; entry < queue.size(); entry++) {
        auto& uop = queue.front();
        if (rsSize_[RS_Index] == maxReservationStationSize_[RS_Index]) {
          rsStalls_++;
          break;
        }
        resourceAllocation(uop, port.first);
        queue.pop_front();
      }
    }
  }

  // Allocate reosurces to incoming instructions or add them to stall queue if RS is full
  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    uint8_t port = portAllocator_.allocate(uop->getGroup());
    uint8_t RS_Index = portMapping_[port].first;
    assert(RS_Index < readyQueues_.size() && "Allocated port inaccessible");

    if (rsSize_[RS_Index] == maxReservationStationSize_[RS_Index]) {
      rsStalls_++;
      stallQueues_[RS_Index][portMapping_[port].second].second.push_back(std::move(uop));

      input_.getHeadSlots()[slot] = nullptr;      
      continue;
    }

    resourceAllocation(uop, port);
    input_.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::resourceAllocation(std::shared_ptr<Instruction> uop, uint8_t port) {
    // Get RS information
    uint8_t RS_Index = portMapping_[port].first;
    uint8_t RS_Port = portMapping_[port].second;
    
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
      readyQueues_[RS_Index][RS_Port].second.push_back(std::move(uop));
    }

    rsSize_[RS_Index]++;
}

void DispatchIssueUnit::issue() {
  int issued = 0;
  // Check the ready queues, and issue an instruction from each if the
  // corresponding port isn't blocked
  for (size_t i = 0; i < issuePorts_.size(); i++) {
    uint8_t readyQueueIndex = portMapping_[i].first;
    auto& queue = readyQueues_[readyQueueIndex][portMapping_[i].second].second;
    if (issuePorts_[i].isStalled()) {
      if (queue.size() > 0) {
        portBusyStalls_++; 
      }
      continue;
    }

    if (queue.size() > 0) {
      // Assign the instruction to the port
      auto& uop = queue.front();
      issuePorts_[i].getTailSlots()[0] = std::move(uop);
      queue.pop_front();

      // Inform the port allocator that an instruction issued
      portAllocator_.issued(i);
      issued++;

      assert(rsSize_[readyQueueIndex] > 0);
      rsSize_[readyQueueIndex]--;
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
        auto rsInfo = portMapping_[entry.port];
        readyQueues_[rsInfo.first][rsInfo.second].second.push_back(std::move(entry.uop));
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
    // Search the ready and stall queues for flushed instructions and remove them
    auto& readyQueue = readyQueues_[i];
    auto& stallQueue = stallQueues_[i];
    for (auto& port : readyQueue) {
      auto it = port.second.begin();
      while (it != port.second.end()) {
        auto& uop = *it;
        if (uop->isFlushed()) {
          portAllocator_.deallocate(port.first);
          it = port.second.erase(it);
          assert(rsSize_[i] > 0);
          rsSize_[i]--;
        } else {
          it++;
        }
      }
    }
    for (auto& port : stallQueue) {
      auto it = port.second.begin();
      while (it != port.second.end()) {
        auto& uop = *it;
        if (uop->isFlushed()) {
          portAllocator_.deallocate(port.first);
          it = port.second.erase(it);
        } else {
          it++;
        }
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
        auto readyQueueIndex = portMapping_[dependencyList[i].port].first;
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
