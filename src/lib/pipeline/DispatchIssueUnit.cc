#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <algorithm>
#include <iostream>

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    OperandBypassMap& bypassMap,
    const std::vector<uint16_t>& physicalRegisterStructure,
    ryml::ConstNodeRef config)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator),
      operandBypassMap_(bypassMap) {
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
  // Create set of reservation station structs with correct issue port
  // mappings
  for (size_t i = 0; i < config["Reservation-Stations"].num_children(); i++) {
    // Iterate over each reservation station in config
    auto reservation_station = config["Reservation-Stations"][i];
    // Create ReservationStation struct to be stored
    ReservationStation rs = {
        reservation_station["Size"].as<uint32_t>(),
        reservation_station["Dispatch-Rate"].as<uint16_t>(),
        0ul,
        {}};
    // Resize rs port attribute to match what's defined in config file
    rs.ports.resize(reservation_station["Port-Nums"].num_children());
    for (size_t j = 0; j < reservation_station["Port-Nums"].num_children();
         j++) {
      // Iterate over issue ports in config
      uint16_t issue_port = reservation_station["Port-Nums"][j].as<uint16_t>();
      rs.ports[j].issuePort = issue_port;
      // Add port mapping entry, resizing vector if needed
      if ((size_t)(issue_port + 1) > portMapping_.size()) {
        portMapping_.resize((issue_port + 1));
      }
      portMapping_[issue_port] = {i, j};
    }
    reservationStations_.push_back(rs);
  }

  dispatches_ = std::make_unique<uint16_t[]>(reservationStations_.size());
}

void DispatchIssueUnit::tick() {
  input_.stall(false);
  ticks_++;

  // Reset the array
  std::fill_n(dispatches_.get(), reservationStations_.size(), 0);

  // Check if waiting instructions are ready.
  if (waitingInstructions_.find(ticks_) != waitingInstructions_.end()) {
    // Loop over all pairs in vector
    for (auto& waitPair : waitingInstructions_[ticks_]) {
      auto& depEntry = waitPair.first;
      auto& regValue = waitPair.second;
      // Supply operand
      depEntry.uop->supplyOperand(depEntry.operandIndex, regValue);
      if (depEntry.uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        auto rsInfo = portMapping_[depEntry.port];
        reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
            std::move(depEntry.uop));
      }
    }
    // Once all operands have been supplied, remove map entry
    waitingInstructions_.erase(ticks_);
  }

  // Check if uops with a non-bypassable dependancy are ready.
  auto itDep = dependantInstructions_.begin();
  while (itDep != dependantInstructions_.end()) {
    const auto& reg = itDep->uop->getSourceRegisters()[itDep->operandIndex];
    if (scoreboard_[reg.type][reg.tag]) {
      // The scoreboard says it's ready; read and supply the register value
      itDep->uop->supplyOperand(itDep->operandIndex, registerFileSet_.get(reg));
      if (itDep->uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        auto rsInfo = portMapping_[itDep->port];
        reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
            std::move(itDep->uop));
      }

      itDep = dependantInstructions_.erase(itDep);
    } else {
      itDep++;
    }
  }

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    const std::vector<uint16_t>& supportedPorts = uop->getSupportedPorts();
    if (uop->exceptionEncountered()) {
      // Exception; mark as ready to commit, and remove from pipeline
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }
    // Allocate issue port to uop
    uint16_t port = portAllocator_.allocate(supportedPorts);
    uint16_t RS_Index = portMapping_[port].first;
    uint16_t RS_Port = portMapping_[port].second;
    assert(RS_Index < reservationStations_.size() &&
           "Allocated port inaccessible");
    ReservationStation& rs = reservationStations_[RS_Index];

    // When appropriate, stall uop or input buffer if stall buffer full
    if (rs.currentSize == rs.capacity ||
        dispatches_[RS_Index] == rs.dispatchRate) {
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
    auto& sourceRegisters = uop->getSourceRegisters();
    for (uint16_t i = 0; i < sourceRegisters.size(); i++) {
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
    dispatches_[RS_Index]++;
    rs.currentSize++;
    uop->setDispatched();

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
      auto& uop = queue.front();
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
                                        const span<RegisterValue>& values,
                                        const uint16_t producerGroup) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (size_t i = 0; i < registers.size(); i++) {
    const auto& reg = registers[i];
    // Supply the value to all dependent uops
    auto& dependents = dependencyMatrix_[reg.type][reg.tag];
    for (auto& entry : dependents) {
      int64_t bypassLatency = operandBypassMap_.getBypassLatency(
          producerGroup, entry.uop->getGroup(), reg.type);

      switch (bypassLatency) {
        case -1: {
          // No bypass allowed, add to dependantInstructions_
          dependantInstructions_.push_back(entry);
          break;
        }
        case 0: {
          // No bypass latency, can supply operand
          entry.uop->supplyOperand(entry.operandIndex, values[i]);
          if (entry.uop->canExecute()) {
            // Add the now-ready instruction to the relevant ready queue
            auto rsInfo = portMapping_[entry.port];
            reservationStations_[rsInfo.first]
                .ports[rsInfo.second]
                .ready.push_back(std::move(entry.uop));
          }
          break;
        }
        default: {
          // Some bypass latency to adhear to, add to waitingInstructions_
          assert(bypassLatency > 0 &&
                 "Negative bypass latency other than -1 is not valid.");
          uint64_t releaseOnTick = ticks_ + bypassLatency;
          // Make vector containing new entry
          std::vector<std::pair<dependencyEntry, RegisterValue>> vec = {
              std::make_pair(entry, values[i])};
          // If entries for this tick already exist, then add these to the new
          // vector
          if (waitingInstructions_.find(releaseOnTick) !=
              waitingInstructions_.end()) {
            vec.insert(vec.end(), waitingInstructions_[releaseOnTick].begin(),
                       waitingInstructions_[releaseOnTick].end());
          }
          waitingInstructions_[releaseOnTick] = vec;
          break;
        }
      }
    }
    // Clear the dependency list
    dependencyMatrix_[reg.type][reg.tag].clear();
  }
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

  // Create flushed map to track flushed instructions that appear in multiple
  // data structures.
  //  - Key = RS id
  //  - Value = sequenceID
  std::unordered_map<uint16_t, std::unordered_set<uint64_t>> flushed;

  // Vector to store how many times each port should be deallocated from
  std::vector<uint64_t> portDeallocations(portMapping_.size(), 0);

  // Collect flushed instructions from the dependency matrix and store
  // flushed instructions
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      auto itEntry = dependencyList.begin();
      while (itEntry != dependencyList.end()) {
        if (itEntry->uop->isFlushed()) {
          const uint16_t rsIndex = portMapping_[itEntry->port].first;
          auto insertRet =
              flushed[rsIndex].insert(itEntry->uop->getSequenceId());
          if (insertRet.second) {
            // If insets occurred (i.e. we see this uop for the first time),
            // then increment portDeallocations
            portDeallocations[itEntry->port]++;
          }
          itEntry = dependencyList.erase(itEntry);
        } else {
          itEntry++;
        }
      }
    }
  }

  // Collect flushed instructions from the dependantInstructions_ vector
  auto itDepInsn = dependantInstructions_.begin();
  while (itDepInsn != dependantInstructions_.end()) {
    if (itDepInsn->uop->isFlushed()) {
      const uint16_t rsIndex = portMapping_[itDepInsn->port].first;
      auto insertRet = flushed[rsIndex].insert(itDepInsn->uop->getSequenceId());
      if (insertRet.second) {
        // If insets occurred (i.e. we see this uop for the first time), then
        // increment portDeallocations
        portDeallocations[itDepInsn->port]++;
      }
      itDepInsn = dependantInstructions_.erase(itDepInsn);
    } else {
      itDepInsn++;
    }
  }

  // Collect flushed instructions from the waitingInstructions_ map
  for (auto& mapEntry : waitingInstructions_) {
    auto it = mapEntry.second.begin();
    while (it != mapEntry.second.end()) {
      auto& depEntry = it->first;
      if (depEntry.uop->isFlushed()) {
        const uint16_t rsIndex = portMapping_[depEntry.port].first;
        auto insertRet = flushed[rsIndex].insert(depEntry.uop->getSequenceId());
        if (insertRet.second) {
          // If insets occurred (i.e. we see this uop for the first time), then
          // increment portDeallocations
          portDeallocations[itDepInsn->port]++;
        }
        it = mapEntry.second.erase(it);
      } else {
        it++;
      }
    }
  }

  // For all collected flushed instructions, reduce RS sizes by correct amounts
  for (auto& rsSet : flushed) {
    assert(reservationStations_[rsSet.first].currentSize >=
           rsSet.second.size());
    reservationStations_[rsSet.first].currentSize -= rsSet.second.size();
  }

  // For all ports, deallocate the number of instructions flushed that were
  // mapped to that port
  for (size_t port = 0; port < portDeallocations.size(); port++) {
    portAllocator_.deallocate(portDeallocations[port]);
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

void DispatchIssueUnit::getRSSizes(std::vector<uint32_t>& sizes) const {
  for (auto& rs : reservationStations_) {
    sizes.push_back(rs.capacity - rs.currentSize);
  }
}

void DispatchIssueUnit::updateScoreboard(const Register& reg) {
  scoreboard_[reg.type][reg.tag] = true;
}

}  // namespace pipeline
}  // namespace simeng
