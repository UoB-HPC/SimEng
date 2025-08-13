#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <algorithm>
#include <iostream>

namespace simeng {
namespace pipeline {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    const RegisterFileSet& registerFileSet, PortAllocator& portAllocator,
    const std::vector<uint16_t>& physicalRegisterStructure,
    const ryml::ConstNodeRef config)
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
      const auto issue_port =
          reservation_station["Port-Nums"][j].as<uint16_t>();
      rs.ports[j].issuePort = issue_port;
      // Add port mapping entry, resizing vector if needed
      if (static_cast<size_t>(issue_port + 1) > portMapping_.size()) {
        portMapping_.resize(issue_port + 1);
      }
      portMapping_[issue_port] = {i, j};
    }
    reservationStations_.push_back(rs);
  }
  for (uint16_t i = 0; static_cast<size_t>(i) < reservationStations_.size();
       i++)
    flushed_.emplace(i, std::initializer_list<std::shared_ptr<Instruction>>{});

  dispatches_ = std::make_unique<uint16_t[]>(reservationStations_.size());
}

void DispatchIssueUnit::tick() {
  input_.stall(false);

  // Reset the array
  std::fill_n(dispatches_.get(), reservationStations_.size(), 0);

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    std::vector<uint16_t> supportedPorts = uop->getSupportedPorts();
    if (uop->exceptionEncountered()) {
      // Exception; mark as ready to commit, and remove from pipeline
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }

    // Loop through all ports and remove any who's RS is at capacity or dispatch
    // rate has been met
    auto portIt = supportedPorts.begin();
    while (portIt != supportedPorts.end()) {
      const uint16_t RS_Index = portMapping_[*portIt].first;
      const auto& rs = reservationStations_[RS_Index];
      if (rs.currentSize == rs.capacity ||
          dispatches_[RS_Index] == rs.dispatchRate) {
        portIt = supportedPorts.erase(portIt);
      } else {
        ++portIt;
      }
    }

    // If offloaded, don't allocate RS slots
    if (uop->isOffloaded()) {
      // Identify remaining missing registers and supply values
      auto& sourceRegisters = uop->getSourceRegisters();
      for (uint16_t i = 0; static_cast<size_t>(i) < sourceRegisters.size();
           i++) {
        const auto& reg = sourceRegisters[i];
        if (uop->isOperandOffloaded(i) || uop->isOperandReady(i)) continue;

        // The operand hasn't already been supplied
        if (scoreboard_[reg.type][reg.tag]) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(i, registerFileSet_.get(reg));
        } else {
          // This register isn't ready yet. Register this uop to the dependency
          // matrix for a more efficient lookup later

          // The port is hard-coded 0 because offloaded instructions don't get
          // allocated to reservation stations. This should not matter since
          // the port is only used when an instruction is ready to be executed,
          // and offloaded instructions are never ready to execute (on the core)
          dependencyMatrix_[reg.type][reg.tag].push_back({uop, 0, i});
        }
      }

      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }

    // If no ports left, stall and return
    if (supportedPorts.empty()) {
      input_.stall(true);
      rsStalls_++;
      return;
    }

    // Find an available RS
    const uint16_t port = portAllocator_.allocate(supportedPorts);
    const uint16_t RS_Index = portMapping_[port].first;
    const uint16_t RS_Port = portMapping_[port].second;
    assert(RS_Index < reservationStations_.size() &&
           "Allocated port inaccessible");
    auto& rs = reservationStations_[RS_Index];

    // Assume the uop will be ready
    bool ready = true;

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getSourceRegisters();
    for (uint16_t i = 0; static_cast<size_t>(i) < sourceRegisters.size(); i++) {
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
    ++dispatches_[RS_Index];
    ++rs.currentSize;

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
    auto& rs = reservationStations_[portMapping_[i].first];
    auto& queue = rs.ports[portMapping_[i].second].ready;
    if (issuePorts_[i].isStalled()) {
      if (!queue.empty()) {
        portBusyStalls_++;
      }
      continue;
    }

    if (!queue.empty()) {
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
                                        const span<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (size_t i = 0; i < registers.size(); i++) {
    const auto& reg = registers[i];
    // Flag scoreboard as ready now result is available
    scoreboard_[reg.type][reg.tag] = true;

    // Supply the value to all dependent uops
    auto& dependents = dependencyMatrix_[reg.type][reg.tag];
    for (auto& [uop, port, operandIndex] : dependents) {
      uop->supplyOperand(operandIndex, values[i]);
      if (uop->canExecute() && !uop->isOffloaded()) {
        // Add the now-ready instruction to the relevant ready queue
        const auto [fst, snd] = portMapping_[port];
        reservationStations_[fst].ports[snd].ready.push_back(std::move(uop));
      }
    }

    // Clear the dependency list
    dependencyMatrix_[reg.type][reg.tag].clear();
  }
}

void DispatchIssueUnit::purgeFlushed() {
  for (auto& rs : reservationStations_) {
    // Search the ready queues for flushed instructions and remove them
    for (auto& [issuePort, ready] : rs.ports) {
      // Ready queue
      auto readyIter = ready.begin();
      while (readyIter != ready.end()) {
        const auto& uop = *readyIter;
        if (uop->isFlushed()) {
          portAllocator_.deallocate(issuePort);
          readyIter = ready.erase(readyIter);
          assert(rs.currentSize > 0);
          --rs.currentSize;
        } else {
          ++readyIter;
        }
      }
    }
  }

  // Collect flushed instructions and remove them from the dependency matrix
  for (auto& [fst, snd] : flushed_) snd.clear();
  for (auto& registerType : dependencyMatrix_) {
    for (auto& dependencyList : registerType) {
      auto it = dependencyList.begin();
      while (it != dependencyList.end()) {
        auto& entry = *it;
        if (entry.uop->isFlushed()) {
          if (!entry.uop->isOffloaded()) {
            auto rsIndex = portMapping_[entry.port].first;
            if (!flushed_[rsIndex].count(entry.uop)) {
              flushed_[rsIndex].insert(entry.uop);
              portAllocator_.deallocate(entry.port);
            }
          }
          it = dependencyList.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  // Update reservation station size
  for (uint8_t i = 0; static_cast<size_t>(i) < reservationStations_.size();
       i++) {
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

void DispatchIssueUnit::getRSSizes(std::vector<uint32_t>& sizes) const {
  for (auto& rs : reservationStations_) {
    sizes.push_back(rs.capacity - rs.currentSize);
  }
}

}  // namespace pipeline
}  // namespace simeng
