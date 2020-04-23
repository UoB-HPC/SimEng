#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <unordered_set>

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure,
    std::vector<std::pair<uint8_t, uint64_t>> rsArrangement,
    uint8_t dispatchRate)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator),
      dispatchRate_(dispatchRate) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
  
  for (int port = 0; port < rsArrangement.size(); port++) {
    auto RS = rsArrangement[port];
    if (reservationStations_.size() < RS.first + 1) {
      reservationStations_.resize(RS.first + 1, {0, 0, *(new std::vector<ReservationStationPort>)});
    }
    reservationStations_[RS.first].capacity = RS.second;
    // Find number of ports already mapping to the given RS
    uint8_t port_index = 0;
    for (auto rsPort : portMapping_){
      if (rsPort.first == RS.first) { port_index++; }
    }
    // Add port
    portMapping_.push_back({RS.first, port_index});
    reservationStations_[RS.first].ports.resize(port_index + 1);
    reservationStations_[RS.first].ports[port_index].issuePort = port;
  }
};

void DispatchIssueUnit::tick() {
  std::vector<uint8_t> dispatches(reservationStations_.size(), 0);
  for (int i = 0; i < reservationStations_.size(); i++) {
    auto& rs = reservationStations_[i];
    while((rs.currentSize < rs.capacity) && (rs.stalled.size() > 0) && dispatches[i] < dispatchRate_) {
      auto& entry = rs.stalled.front();
      if (entry.second->isLoad() || entry.second->isStore()) {
        if (rs.currentSize + entry.second->getStallCycles() > rs.capacity) {
          rs.pausedId = entry.second->getSequenceId();
          break;
        } else {
          dispatches[i] += entry.second->getStallCycles() - 1;
          rs.currentSize += entry.second->getStallCycles() - 1;
          if (rs.pausedId == entry.second->getSequenceId()) { rs.pausedId = -1; }
        }
      }
      entry.second->setDispatchStalled_(false);
      if (entry.second->canExecute()) {
        rs.ports[portMapping_[entry.first].second].ready.push_back(std::move(entry.second));
      }
      rs.stalled.pop_front();
      dispatches[i]++;
      rs.currentSize++;
    }
    if (rs.stalled.size() > 0) { rsStalls_++; }
  }

  input_.stall(false);

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    uint8_t port = portAllocator_.allocate(uop->getGroup());
    uint8_t RS_Index = portMapping_[port].first;
    uint8_t RS_Port = portMapping_[port].second;

    assert(RS_Index < reservationStations_.size() && "Allocated port inaccessible");

    ReservationStation& rs = reservationStations_[RS_Index];

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

    if (rs.pausedId != -1 || rs.currentSize == rs.capacity || dispatches[RS_Index] > dispatchRate_) {
      uop->setDispatchStalled_(true);
      rs.stalled.push_back({port, std::move(uop)});

      input_.getHeadSlots()[slot] = nullptr;
      continue;
    } else if ((uop->isLoad() || uop->isStore()) && ((rs.currentSize + uop->getStallCycles()) > rs.capacity)) {
      rs.pausedId = uop->getSequenceId();
      uop->setDispatchStalled_(true);
      rs.stalled.push_back({port, std::move(uop)});

      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }
    
    dispatches[RS_Index]++;
    rs.currentSize++;

    if(uop->isLoad() || uop->isStore()) {
      dispatches[RS_Index] += (uop->getStallCycles() - 1);
      rs.currentSize += (uop->getStallCycles() - 1);
    }

    if (ready) {
      rs.ports[RS_Port].ready.push_back(std::move(uop));
    }
    
    input_.getHeadSlots()[slot] = nullptr;
  }
}

void DispatchIssueUnit::issue() {
  int issued = 0;
  // Check the ready queues, and issue an instruction from each if the
  // corresponding port isn't blocked
  for (size_t i = 0; i < issuePorts_.size(); i++) {
    ReservationStation& rs = reservationStations_[portMapping_[i].first];
    auto& queue = rs.ports[portMapping_[i].second].ready;
    if (issuePorts_[i].isStalled()) {
      if (queue.size() > 0) {
        portBusyStalls_++;
      }
      continue;
    }

    if (queue.size() > 0) {
      // Assign the instruction to the port
      auto& uop = queue.front();
      if(uop->isLoad() || uop->isStore()) {
        rs.currentSize -= (uop->getStallCycles() - 1);
      }
      issuePorts_[i].getTailSlots()[0] = std::move(uop);
      queue.pop_front();

      // Inform the port allocator that an instruction issued
      portAllocator_.issued(i);
      issued++;
      assert(rs.currentSize > 0);
      rs.currentSize--;
    }
  }

  if (issued == 0) {
    bool empty = true;
    for(auto entry : reservationStations_) {
      if(entry.currentSize != 0) {
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
        if (!entry.uop->isDispatchStalled_()) {
          // Add the now-ready instruction to the relevant ready queue
          auto rsInfo = portMapping_[entry.port];
          reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(std::move(entry.uop));
        }
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
  for (size_t i = 0; i < reservationStations_.size(); i++) {
    // Search the ready and stall queues for flushed instructions and remove them
    auto& rs = reservationStations_[i];
    for (auto& port : rs.ports) {
      // Ready queue
      auto readyIter = port.ready.begin();
      while (readyIter != port.ready.end()) {
        auto& uop = *readyIter;
        if (uop->isFlushed()) {
          if(uop->isLoad() || uop->isStore()) {
            rs.currentSize -= (uop->getStallCycles() - 1);
          }
          portAllocator_.deallocate(port.issuePort);
          readyIter = port.ready.erase(readyIter);
          assert(rs.currentSize > 0);
          rs.currentSize--;
        } else {
          readyIter++;
        }
      }
    }
    // Stall queue
    auto stallIter = rs.stalled.begin();
    while (stallIter != rs.stalled.end()) {
      auto& entry = (*stallIter);
      if (entry.second->isFlushed()) {
        if((entry.second->isLoad() || entry.second->isStore()) && (rs.pausedId == entry.second->getSequenceId())) {
          rs.pausedId = -1;
        }
        portAllocator_.deallocate(entry.first);
        stallIter = rs.stalled.erase(stallIter);
      } else {
        stallIter++;
      }
    }
  }

  // Collect flushed instructions and remove them from the dependency matrix
  std::vector<std::unordered_set<std::shared_ptr<Instruction>>> flushed(reservationStations_.size(), 
    *(new std::unordered_set<std::shared_ptr<Instruction>>));
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      // Instructions are added in-order, so flushed instructions will be at the
      // back of each dependency list. Walk backwards through the list and add
      // the flushed instructions to the set.
      int i;
      for (i = dependencyList.size() - 1; i >= 0; i--) {
        auto& uop = dependencyList[i].uop;
        auto rsIndex = portMapping_[dependencyList[i].port].first;
        if (!uop->isFlushed()) {
          // Stop at first (newest) non-flushed instruction
          break;
        }
        if (!flushed[rsIndex].count(uop)) {
          if(!uop->isDispatchStalled_()) {
            flushed[rsIndex].insert(uop);
            if(uop->isLoad() || uop->isStore()) {
              reservationStations_[rsIndex].currentSize -= (uop->getStallCycles() - 1);
            }
            // Inform the allocator we've removed an instruction
            portAllocator_.deallocate(dependencyList[i].port);
          }
        }
      }
      // Resize the dependency list to remove flushed instructions from it
      dependencyList.resize(i + 1);
    }
  }

  // Update reservation station size
  for(int i = 0; i < reservationStations_.size(); i++) {
    assert(reservationStations_[i].currentSize >= flushed[i].size());
    reservationStations_[i].currentSize -= flushed[i].size();
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

void DispatchIssueUnit::getRSSizes(std::vector<uint64_t>& sizes) const {
  for (auto& rs : reservationStations_) {
    sizes.push_back(rs.capacity - rs.currentSize);
  }
}

}  // namespace pipeline
}  // namespace simeng
