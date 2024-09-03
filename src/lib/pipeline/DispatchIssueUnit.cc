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
    const std::vector<uint16_t>& physicalRegisterStructure)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator),
      operandBypassMap_(bypassMap) {
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
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
        config::SimInfo::getValue<uint16_t>(reservation_station["Size"]),
        config::SimInfo::getValue<uint16_t>(
            reservation_station["Dispatch-Rate"]),
        0,
        {}};
    // Resize rs port attribute to match what's defined in config file
    rs.ports.resize(reservation_station["Port-Nums"].num_children());
    for (size_t j = 0; j < reservation_station["Port-Nums"].num_children();
         j++) {
      // Iterate over issue ports in config
      uint16_t issue_port = config::SimInfo::getValue<uint16_t>(
          reservation_station["Port-Nums"][j]);
      rs.ports[j].issuePort = issue_port;
      // Add port mapping entry, resizing vector if needed
      if ((issue_port + 1) > portMapping_.size()) {
        portMapping_.resize((issue_port + 1));
      }
      portMapping_[issue_port] = {i, j};
    }
    reservationStations_.push_back(rs);
  }
  for (uint16_t i = 0; i < reservationStations_.size(); i++)
    flushed_.emplace(i, std::initializer_list<std::shared_ptr<Instruction>>{});

  dispatches_ = std::make_unique<uint16_t[]>(reservationStations_.size());
  possibleIssues_.resize(issuePorts_.size());
  actualIssues_.resize(issuePorts_.size());
  frontendStallsPort_.resize(issuePorts_.size());
  backendStallsPort_.resize(issuePorts_.size());
  rsStallsPort_.resize(reservationStations_.size());
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
    const auto& reg = itDep->uop->getOperandRegisters()[itDep->operandIndex];
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
    // std::cerr << "Allocating port for " << std::hex
    //           << uop->getInstructionAddress() << std::dec << std::endl;
    uint16_t port =
        portAllocator_.allocate(supportedPorts, uop->getStallCycles());
    uint16_t RS_Index = portMapping_[port].first;
    uint16_t RS_Port = portMapping_[port].second;
    assert(RS_Index < reservationStations_.size() &&
           "Allocated port inaccessible");
    ReservationStation& rs = reservationStations_[RS_Index];

    // When appropriate, stall uop or input buffer if stall buffer full
    if (rs.currentSize == rs.capacity ||
        dispatches_[RS_Index] == rs.dispatchRate) {
      // Deallocate port given
      portAllocator_.deallocate(port, uop->getStallCycles());
      input_.stall(true);
      rsStalls_++;
      rsStallsPort_[RS_Index]++;
      return;
    }

    // Assume the uop will be ready
    bool ready = true;

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getOperandRegisters();
    for (uint16_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];
      // std::cerr << std::hex << uop->getInstructionAddress() << std::dec <<
      // ":"
      //           << uop->getSequenceId() << std::endl;
      // std::cerr << "\tGet reg " << i << " " << unsigned(reg.type) << ":"
      //           << reg.tag << std::endl;

      if (!uop->isOperandReady(i)) {
        // The operand hasn't already been supplied
        if (scoreboard_[reg.type][reg.tag]) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(i, registerFileSet_.get(reg));
          // std::cerr << "\t\tGot" << std::endl;
        } else {
          // This register isn't ready yet. Register this uop to the dependency
          // matrix for a more efficient lookup later
          dependencyMatrix_[reg.type][reg.tag].push_back({uop, port, i});
          ready = false;
          // std::cerr << "\t\tDependent" << std::endl;
        }
      } else {
        // std::cerr << "\t\tReady" << std::endl;
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
        backendStallsPort_[i]++;
        portBusyStalls_++;
      }
      frontendStallsPort_[i]++;
      continue;
    }

    if (queue.size() > 0) {
      auto& uop = queue.front();

      const std::vector<uint16_t>& supportedPorts = uop->getSupportedPorts();
      for (const auto& pt : supportedPorts) possibleIssues_[pt]++;
      actualIssues_[i]++;

      // Inform the port allocator that an instruction issued
      portAllocator_.issued(i, uop->getStallCycles());
      issued++;

      issuePorts_[i].getTailSlots()[0] = std::move(uop);
      queue.pop_front();

      assert(rs.currentSize > 0);
      rs.currentSize--;
    } else {
      frontendStallsPort_[i]++;
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
          // std::cerr << groupOptions_[producerGroup] << " cannot pass to "
          //           << groupOptions_[entry.uop->getGroup()] << " in port "
          //           << portNames_[entry.port] << std::endl;
          // No bypass allowed, add to dependantInstructions_
          dependantInstructions_.push_back(entry);
          break;
        }
        case 0: {
          // std::cerr << groupOptions_[producerGroup] << " can pass to "
          //           << groupOptions_[entry.uop->getGroup()]
          //           << " with latency 0 in port " << portNames_[entry.port]
          //           << std::endl;
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
          // std::cerr << groupOptions_[producerGroup] << " can pass to "
          //           << groupOptions_[entry.uop->getGroup()] << " with latency
          //           "
          //           << bypassLatency << " in port " << portNames_[entry.port]
          //           << std::endl;
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
          portAllocator_.deallocate(port.issuePort, uop->getStallCycles());
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
          const uint16_t rsIndex = portMapping_[entry.port].first;
          if (!flushed_[rsIndex].count(entry.uop)) {
            flushed_[rsIndex].insert(entry.uop);
            portAllocator_.deallocate(entry.port, entry.uop->getStallCycles());
          }
          it = dependencyList.erase(it);
        } else {
          it++;
        }
      }
    }
  }

  // Collect flushed instructions from the dependantInstructions_ vector
  auto itDepInsn = dependantInstructions_.begin();
  while (itDepInsn != dependantInstructions_.end()) {
    if (itDepInsn->uop->isFlushed()) {
      const uint16_t rsIndex = portMapping_[itDepInsn->port].first;
      if (!flushed_[rsIndex].count(itDepInsn->uop)) {
        flushed_[rsIndex].insert(itDepInsn->uop);
        portAllocator_.deallocate(itDepInsn->port,
                                  itDepInsn->uop->getStallCycles());
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
        if (!flushed_[rsIndex].count(depEntry.uop)) {
          flushed_[rsIndex].insert(depEntry.uop);
          portAllocator_.deallocate(depEntry.port,
                                    depEntry.uop->getStallCycles());
        }
        it = mapEntry.second.erase(it);
      } else {
        it++;
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
std::vector<uint64_t> DispatchIssueUnit::getRSStallsPort() const {
  return rsStallsPort_;
}

uint64_t DispatchIssueUnit::getFrontendStalls() const {
  return frontendStalls_;
}
std::vector<uint64_t> DispatchIssueUnit::getFrontendStallsPort() const {
  return frontendStallsPort_;
}

uint64_t DispatchIssueUnit::getBackendStalls() const { return backendStalls_; }
std::vector<uint64_t> DispatchIssueUnit::getBackendStallsPort() const {
  return backendStallsPort_;
}

uint64_t DispatchIssueUnit::getPortBusyStalls() const {
  return portBusyStalls_;
}

void DispatchIssueUnit::getRSSizes(std::vector<uint64_t>& sizes) const {
  for (auto& rs : reservationStations_) {
    sizes.push_back(rs.capacity - rs.currentSize);
  }
}

void DispatchIssueUnit::updateScoreboard(const Register& reg) {
  scoreboard_[reg.type][reg.tag] = true;
}

void DispatchIssueUnit::flush() {
  for (size_t i = 0; i < scoreboard_.size(); i++) {
    for (size_t j = 0; j < scoreboard_[i].size(); j++) {
      scoreboard_[i][j] = true;
    }
  }

  for (size_t i = 0; i < dependencyMatrix_.size(); i++) {
    for (size_t j = 0; j < dependencyMatrix_[i].size(); j++) {
      dependencyMatrix_[i][j].clear();
    }
  }
}

const std::vector<uint64_t> DispatchIssueUnit::getPossibleIssues() const {
  return possibleIssues_;
}
const std::vector<uint64_t> DispatchIssueUnit::getActualIssues() const {
  return actualIssues_;
}

void DispatchIssueUnit::resetStats() {
  // rsStalls_ = 0;
  // frontendStalls_ = 0;
  // backendStalls_ = 0;
  // portBusyStalls_ = 0;

  // possibleIssues_ = {};
  // actualIssues_ = {};
  // possibleIssues_.resize(issuePorts_.size());
  // actualIssues_.resize(issuePorts_.size());

  // frontendStallsPort_ = {};
  // backendStallsPort_ = {};
  // rsStallsPort_ = {};
  // frontendStallsPort_.resize(issuePorts_.size());
  // backendStallsPort_.resize(issuePorts_.size());
  // rsStallsPort_.resize(reservationStations_.size());
}

}  // namespace pipeline
}  // namespace simeng
