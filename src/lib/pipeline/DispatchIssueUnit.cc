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
    ryml::ConstNodeRef config)
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
  for (uint16_t i = 0; i < reservationStations_.size(); i++)
    flushed_.emplace(i, std::initializer_list<std::shared_ptr<Instruction>>{});

  dispatches_ = std::make_unique<uint16_t[]>(reservationStations_.size());
  frontendSlotStalls_ = std::vector<uint64_t>(issuePorts_.size(), 0);
  backendSlotStalls_ = std::vector<uint64_t>(issuePorts_.size(), 0);
  rsMiss_ = std::vector<std::vector<uint64_t>>(
      issuePorts_.size(),
      std::vector<uint64_t>(reservationStations_.size(), 0));
  emptyAtIssueNoDeps_ = std::vector<std::vector<uint64_t>>(
      issuePorts_.size(), std::vector<uint64_t>(issuePorts_.size(), 0));
  emptyAtIssueWithDeps_ = std::vector<std::vector<uint64_t>>(
      issuePorts_.size(), std::vector<uint64_t>(issuePorts_.size(), 0));
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

    const std::vector<uint16_t>& supportedPorts = uop->getSupportedPorts();
    if (uop->exceptionEncountered()) {
      // Exception; mark as ready to commit, and remove from pipeline
      uop->setCommitReady();
      input_.getHeadSlots()[slot] = nullptr;
      continue;
    }
    // Allocate issue port to uop
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
      for (const auto pt : supportedPorts) {
        uint16_t rsi = portMapping_[pt].first;
        if (rsi != RS_Index) {
          if (reservationStations_[rsi].currentSize !=
                  reservationStations_[rsi].capacity &&
              dispatches_[rsi] != reservationStations_[rsi].dispatchRate) {
            // std::cerr << "Deallocated " << port << " as "
            //           << (rs.currentSize == rs.capacity ? "at capacity"
            //                                             : "exceeded rate")
            //           << " but rs " << rsi << " had space"
            //           << (dispatches_[rsi] !=
            //                       reservationStations_[rsi].dispatchRate
            //                   ? " and rate"
            //                   : "")
            //           << std::endl;
            rsMiss_[port][rsi]++;
          }
        }
      }
      // Deallocate port given
      portAllocator_.deallocate(port, uop->getStallCycles());
      input_.stall(true);
      rsStalls_++;
      backendSlotStalls_[port]++;
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

    if (ready) {
      rs.ports[RS_Port].ready.push_back(std::move(uop));
    } else {
      rs.ports[RS_Port].dependent++;
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
        backendSlotStalls_[i]++;
      } else if (rs.ports[portMapping_[i].second].dependent) {
        backendSlotStalls_[i]++;
      } else {
        frontendSlotStalls_[i]++;
      }
      continue;
    }

    if (queue.size() > 0) {
      auto& uop = queue.front();

      // Get issueGroup
      const std::vector<uint16_t>& supportedPorts = uop->getSupportedPorts();
      uint64_t issueGroup = 0;
      for (const uint16_t& pt : supportedPorts) {
        issueGroup |= (1ull << pt);
      }
      if (issueGroupUsage_.find(issueGroup) == issueGroupUsage_.end()) {
        issueGroupUsage_[issueGroup] = std::vector(issuePorts_.size(), 0ull);
      }
      issueGroupUsage_[issueGroup][i]++;

      issuePorts_[i].getTailSlots()[0] = std::move(uop);
      queue.pop_front();

      // Inform the port allocator that an instruction issued
      portAllocator_.issued(i,
                            issuePorts_[i].getTailSlots()[0]->getStallCycles());
      issued++;

      assert(rs.currentSize > 0);
      rs.currentSize--;
    } else if (rs.ports[portMapping_[i].second].dependent) {
      for (size_t j = 0; j < issuePorts_.size(); j++) {
        if (reservationStations_[portMapping_[j].first]
                .ports[portMapping_[j].second]
                .ready.size() > 1) {
          for (const auto& op : reservationStations_[portMapping_[j].first]
                                    .ports[portMapping_[j].second]
                                    .ready) {
            if (std::find(op->getSupportedPorts().begin(),
                          op->getSupportedPorts().end(),
                          i) != op->getSupportedPorts().end()) {
              emptyAtIssueWithDeps_[i][j]++;
              break;
            }
          }
        }
      }
      backendSlotStalls_[i]++;
    } else {
      for (size_t j = 0; j < issuePorts_.size(); j++) {
        if (reservationStations_[portMapping_[j].first]
                .ports[portMapping_[j].second]
                .ready.size() > 1) {
          for (const auto& op : reservationStations_[portMapping_[j].first]
                                    .ports[portMapping_[j].second]
                                    .ready) {
            if (std::find(op->getSupportedPorts().begin(),
                          op->getSupportedPorts().end(),
                          i) != op->getSupportedPorts().end()) {
              emptyAtIssueNoDeps_[i][j]++;
              break;
            }
          }
        }
      }
      frontendSlotStalls_[i]++;
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
    for (auto& entry : dependents) {
      entry.uop->supplyOperand(entry.operandIndex, values[i]);
      if (entry.uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        auto rsInfo = portMapping_[entry.port];
        auto it = reservationStations_[rsInfo.first]
                      .ports[rsInfo.second]
                      .ready.begin();
        bool inserted = false;
        while (it != reservationStations_[rsInfo.first]
                         .ports[rsInfo.second]
                         .ready.end()) {
          if ((*it)->getSequenceId() > entry.uop->getSequenceId()) {
            reservationStations_[rsInfo.first]
                .ports[rsInfo.second]
                .ready.insert(it, std::move(entry.uop));
            inserted = true;
            break;
          } else {
            it++;
          }
        }
        if (!inserted) {
          reservationStations_[rsInfo.first]
              .ports[rsInfo.second]
              .ready.push_back(std::move(entry.uop));
        }
        if (reservationStations_[rsInfo.first].ports[rsInfo.second].dependent ==
            0) {
          std::cerr << "ERR 0" << std::endl;
          exit(1);
        }
        reservationStations_[rsInfo.first].ports[rsInfo.second].dependent--;
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
          auto rsIndex = portMapping_[entry.port].first;
          if (!flushed_[rsIndex].count(entry.uop)) {
            flushed_[rsIndex].insert(entry.uop);
            portAllocator_.deallocate(entry.port, entry.uop->getStallCycles());
            if (reservationStations_[portMapping_[entry.port].first]
                    .ports[portMapping_[entry.port].second]
                    .dependent == 0) {
              std::cerr << "ERR 1" << std::endl;
              exit(1);
            }
            reservationStations_[portMapping_[entry.port].first]
                .ports[portMapping_[entry.port].second]
                .dependent--;
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

void DispatchIssueUnit::getRSSizes(std::vector<uint32_t>& sizes) const {
  for (auto& rs : reservationStations_) {
    sizes.push_back(rs.capacity - rs.currentSize);
  }
}

}  // namespace pipeline
}  // namespace simeng
