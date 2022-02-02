#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <algorithm>
#include <iostream>
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
  // Create set of reservation station structs with correct issue port mappings
  for (int port = 0; port < rsArrangement.size(); port++) {
    auto RS = rsArrangement[port];
    if (reservationStations_.size() < RS.first + 1) {
      std::vector<ReservationStationPort> ports;
      reservationStations_.resize(RS.first + 1, {0, 0, ports});
    }
    reservationStations_[RS.first].capacity = RS.second;
    // Find number of ports already mapping to the given RS
    uint8_t port_index = 0;
    for (auto rsPort : portMapping_) {
      if (rsPort.first == RS.first) {
        port_index++;
      }
    }
    // Add port
    portMapping_.push_back({RS.first, port_index});
    reservationStations_[RS.first].ports.resize(port_index + 1);
    reservationStations_[RS.first].ports[port_index].issuePort = port;
  }
  dispatches.resize(reservationStations_.size());
  for (uint8_t i = 0; i < reservationStations_.size(); i++)
    flushed_.emplace(i, std::initializer_list<std::shared_ptr<Instruction>>{});
}

void DispatchIssueUnit::tick() {
  input_.stall(false);

  // Reset the counters
  std::fill(dispatches.begin(), dispatches.end(), 0);

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    const std::vector<uint8_t>& supportedPorts = uop->getSupportedPorts();
    if (uop->exceptionEncountered()) {
      // Exception; mark as ready to commit, and remove from pipeline
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }
    // Allocate issue port to uop
    uint8_t port = portAllocator_.allocate(supportedPorts);
    uint8_t RS_Index = portMapping_[port].first;
    uint8_t RS_Port = portMapping_[port].second;
    assert(RS_Index < reservationStations_.size() &&
           "Allocated port inaccessible");
    ReservationStation& rs = reservationStations_[RS_Index];

    // When appropriate, stall uop or input buffer if stall buffer full
    if (rs.currentSize == rs.capacity ||
        dispatches[RS_Index] == dispatchRate_) {
      // Deallocate port given
      portAllocator_.deallocate(port);
      input_.stall(true);
      rsStalls_++;
      return;
    }

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

    // Increment dispatches made and RS occupied entries size
    dispatches[RS_Index]++;
    rs.currentSize++;

    if (ready) {
      // std::cout << "Dispatch ready 0x" << std::hex
      //           << uop->getInstructionAddress() << std::dec << std::endl;
      rs.ports[RS_Port].ready.push_back(std::move(uop));
    } else {
      // std::cout << "Dispatch waiting 0x" << std::hex
      //           << uop->getInstructionAddress() << std::dec << std::endl;
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
      // std::cout << "Issue port " << i << "(" << queue.size() << ")"
      //           << std::endl;
      if (queue.size() > 0) {
        portBusyStalls_++;
      }
      continue;
    }

    if (queue.size() > 0) {
      auto& uop = queue.front();
      // std::cout << "Issue 0x" << std::hex << uop->getInstructionAddress()
      //           << std::dec << ": port " << i << std::endl;
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
    for (const auto& rs : reservationStations_) {
      if (rs.currentSize != 0) {
        backendStalls_++;
        return;
      }
    }
    frontendStalls_++;
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
        reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
            std::move(entry.uop));
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
    // Search the ready queues for flushed instructions and remove them
    auto& rs = reservationStations_[i];
    for (auto& port : rs.ports) {
      // Ready queue
      auto readyIter = port.ready.begin();
      while (readyIter != port.ready.end()) {
        auto& uop = *readyIter;
        if (uop->isFlushed()) {
          portAllocator_.deallocate(port.issuePort);
          readyIter = port.ready.erase(readyIter);
          assert(rs.currentSize > 0);
          rs.currentSize--;
        } else {
          readyIter++;
        }
      }
    }
  }

  // Collect flushed instructions and remove them from the dependency matrix
  for (auto& it : flushed_) it.second.clear();
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      auto it = dependencyList.begin();
      while (it != dependencyList.end()) {
        auto& entry = *it;
        if (entry.uop->isFlushed()) {
          auto rsIndex = portMapping_[entry.port].first;
          if (!flushed_[rsIndex].count(entry.uop)) {
            flushed_[rsIndex].insert(entry.uop);
            portAllocator_.deallocate(entry.port);
          }
          it = dependencyList.erase(it);
        } else {
          it++;
        }
      }
    }
  }

  // Update reservation station size
  for (uint8_t i = 0; i < reservationStations_.size(); i++) {
    assert(reservationStations_[i].currentSize >= flushed_[i].size());
    reservationStations_[i].currentSize -= flushed_[i].size();
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
