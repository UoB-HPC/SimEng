#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <algorithm>
#include <iostream>

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure, YAML::Node config)
    : input_(fromRename),
      issuePorts_(issuePorts),
      registerFileSet_(registerFileSet),
      scoreboard_(physicalRegisterStructure.size()),
      dependencyMatrix_(physicalRegisterStructure.size()),
      portAllocator_(portAllocator),
      operandBypassType_(config["Core"]["Operand-Bypass"].as<std::string>()) {
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], true);
    dependencyMatrix_[type].resize(physicalRegisterStructure[type]);
  }
  // Create set of reservation station structs with correct issue port
  // mappings
  for (size_t i = 0; i < config["Reservation-Stations"].size(); i++) {
    // Iterate over each reservation station in config
    auto reservation_station = config["Reservation-Stations"][i];
    // Create ReservationStation struct to be stored
    ReservationStation rs = {
        reservation_station["Size"].as<uint16_t>(),
        reservation_station["Dispatch-Rate"].as<uint16_t>(),
        0,
        {}};
    // Resize rs port attribute to match what's defined in config file
    rs.ports.resize(reservation_station["Ports"].size());
    for (size_t j = 0; j < reservation_station["Ports"].size(); j++) {
      // Iterate over issue ports in config
      uint16_t issue_port = reservation_station["Ports"][j].as<uint16_t>();
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
}

void DispatchIssueUnit::tick() {
  input_.stall(false);
  ticks_++;

  /** Stores the number of instructions dispatched for each
   * reservation station. */
  std::vector<uint16_t> dispatches = {
      0, static_cast<unsigned short>(reservationStations_.size())};

  // Check if waiting instructions are ready.
  auto itWait = waitingInstructions_.find(ticks_);
  if (itWait != waitingInstructions_.end()) {
    auto vec = itWait->second;
    auto itInner = vec.begin();
    // Loop through each vector entry
    while (itInner != vec.end()) {
      auto& entry = itInner->first;
      auto value = itInner->second;

      entry.uop->supplyOperand(entry.operandIndex, value);
      if (entry.uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        auto rsInfo = portMapping_[entry.port];

        reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
            std::move(entry.uop));
      }
      // Increment iterator to next vector element.
      itInner++;
    }
    // Once all entrys have been dispatched, remove map entry
    waitingInstructions_.erase(itWait);
  }

  // Check if uop is ready.
  auto itDep = dependantInstructions_.begin();
  while (itDep != dependantInstructions_.end()) {
    auto& entry = *itDep;
    auto& sourceRegisters = entry.uop->getOperandRegisters();
    const auto& reg = sourceRegisters[entry.operandIndex];

    bool supplied = false;

    if (scoreboard_[reg.type][reg.tag]) {
      // The scoreboard says it's ready; read and supply the register value
      entry.uop->supplyOperand(entry.operandIndex, registerFileSet_.get(reg));
      supplied = true;
    }

    if (entry.uop->canExecute()) {
      // Add the now-ready instruction to the relevant ready queue
      auto rsInfo = portMapping_[entry.port];
      reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
          std::move(entry.uop));
    }

    // Remove completed instructions from dependantInstructions_ or increase
    // iterator
    if (supplied)
      itDep = dependantInstructions_.erase(itDep);
    else
      itDep++;
  }

  // Dispatch from Input Buffer
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
        dispatches[RS_Index] == rs.dispatchRate) {
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

void DispatchIssueUnit::forwardOperands(
    const std::shared_ptr<Instruction> insn) {
  const span<Register>& registers = insn->getDestinationRegisters();
  const span<RegisterValue>& values = insn->getResults();
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (size_t i = 0; i < registers.size(); i++) {
    const auto& reg = registers[i];
    // Flag scoreboard as ready now result is available
    scoreboard_[reg.type][reg.tag] = true;

    // Supply the value to all dependent uops
    const auto& dependents = dependencyMatrix_[reg.type][reg.tag];
    for (auto& entry : dependents) {
      // Forward latency defaults to an all-to-all mapping where latency is
      // always 0.
      int8_t forwardLatency = 0;
      if (operandBypassType_ == "None")
        forwardLatency = -1;
      else if (operandBypassType_ == "Mapping")
        forwardLatency = insn->canForward(insn->getProducerGroup(),
                                          entry.uop->getConsumerGroup());

      if (forwardLatency == 0) {
        // If forwarding latency is 0 then can be issued immediately
        entry.uop->supplyOperand(entry.operandIndex, values[i]);
        if (entry.uop->canExecute()) {
          // Add the now-ready instruction to the relevant ready queue
          auto rsInfo = portMapping_[entry.port];
          reservationStations_[rsInfo.first]
              .ports[rsInfo.second]
              .ready.push_back(std::move(entry.uop));
        }
      } else if (forwardLatency == -1) {
        // Latecy of -1 means no forwarding is permitted.
        dependantInstructions_.push_back(entry);
      } else {
        // Add instruction to waiting list for y ticks
        uint64_t releaseOnTick = ticks_ + forwardLatency;
        // See if other instructions are released on the same ticks_ count
        if (waitingInstructions_.find(releaseOnTick) !=
            waitingInstructions_.end()) {
          // If yes, add this instruction and value pair to the vector
          waitingInstructions_.find(releaseOnTick)
              ->second.push_back(std::make_pair(entry, values[i]));
        } else {
          // If not, create new map entry
          std::vector<std::pair<dependencyEntry, RegisterValue>> vec;
          vec.push_back(std::make_pair(entry, values[i]));
          waitingInstructions_.insert(std::make_pair(releaseOnTick, vec));
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
