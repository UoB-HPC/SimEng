#include "simeng/pipeline/DispatchIssueUnit.hh"

#include <algorithm>
#include <iostream>

namespace simeng {
namespace pipeline {

bool print = false;

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
  assoicatedIssues_.resize(issuePorts_.size());
  missedIssues_.resize(issuePorts_.size());
}

void DispatchIssueUnit::tick() {
  input_.stall(false);
  ticks_++;

  if (print) std::cerr << "=== " << ticks_ << " ===" << std::endl;

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
        if (print)
          std::cerr << "Ready for port " << depEntry.port
                    << " in waitingInstructions_ " << std::hex
                    << depEntry.uop->getInstructionAddress() << std::dec
                    << " - " << depEntry.uop->getSequenceId() << " - "
                    << depEntry.uop->getOpcode() << std::endl;
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
  // auto itDep = dependantInstructions_.begin();
  // while (itDep != dependantInstructions_.end()) {
  //   const auto& reg = itDep->uop->getOperandRegisters()[itDep->operandIndex];
  //   if (scoreboard_[reg.type][reg.tag]) {
  //     // The scoreboard says it's ready; read and supply the register value
  //     itDep->uop->supplyOperand(itDep->operandIndex,
  //     registerFileSet_.get(reg)); if (itDep->uop->canExecute()) {
  //       std::cerr << "Ready in dependantInstructions_ " << std::hex
  //                 << itDep->uop->getInstructionAddress() << std::dec << " - "
  //                 << itDep->uop->getSequenceId() << " - "
  //                 << itDep->uop->getOpcode() << std::endl;
  //       // Add the now-ready instruction to the relevant ready queue
  //       auto rsInfo = portMapping_[itDep->port];
  //       reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
  //           std::move(itDep->uop));
  //     }

  //     itDep = dependantInstructions_.erase(itDep);
  //   } else {
  //     itDep++;
  //   }
  // }

  if (issuePrint_) {
    std::cerr << "[SimEng] Dispatch Queues: [";
    for (size_t slot = 0; slot < input_.getWidth(); slot++) {
      auto& uop = input_.getHeadSlots()[slot];
      if (uop == nullptr)
        std::cerr << "N/A,";
      else
        std::cerr << std::hex << uop->getInstructionAddress() << std::dec
                  << ",";
    }
    std::cerr << "\b]" << std::endl;
  }

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
    // Allocate issue port to uop
    // std::cerr << "Allocating port for " << std::hex
    //           << uop->getInstructionAddress() << std::dec << std::endl;
    // uint16_t port =
    //     portAllocator_.allocate(supportedPorts, uop->getStallCycles());
    // uint16_t RS_Index = portMapping_[port].first;
    // uint16_t RS_Port = portMapping_[port].second;
    // assert(RS_Index < reservationStations_.size() &&
    //        "Allocated port inaccessible");
    // ReservationStation& rs = reservationStations_[RS_Index];

    // // When appropriate, stall uop or input buffer if stall buffer full
    // if (rs.currentSize == rs.capacity ||
    //     dispatches_[RS_Index] == rs.dispatchRate) {
    //   // Deallocate port given
    //   portAllocator_.deallocate(port, uop->getStallCycles());
    //   input_.stall(true);
    //   rsStalls_++;
    //   rsStallsPort_[RS_Index]++;

    //   // std::cerr << "Can't dispatch " << std::hex <<
    //   // uop->getInstructionAddress()
    //   //           << std::dec << " - " << uop->getSequenceId() << " - "
    //   //           << uop->getOpcode() << std::endl;
    //   return;
    // }

    // Loop through all ports and remove any who's RS is at capacity or dispatch
    // rate has been met
    // auto portIt = supportedPorts.begin();
    // while (portIt != supportedPorts.end()) {
    //   uint16_t RS_Index = portMapping_[*portIt].first;
    //   ReservationStation* rs = &reservationStations_[RS_Index];
    //   if (rs->currentSize == rs->capacity ||
    //       dispatches_[RS_Index] == rs->dispatchRate) {
    //     portIt = supportedPorts.erase(portIt);
    //     rsStallsPort_[RS_Index]++;

    //     if (print)
    //       std::cerr << "Dispatched " << std::hex <<
    //       uop->getInstructionAddress()
    //                 << std::dec << " - " << uop->getSequenceId() << " - "
    //                 << uop->getOpcode() << std::endl;
    //   } else {
    //     portIt++;
    //   }
    // }
    // // If no ports left, stall and return
    // if (supportedPorts.size() == 0) {
    //   input_.stall(true);
    //   rsStalls_++;
    //   return;
    // }

    // Find an available RS
    uint16_t port =
        portAllocator_.allocate(supportedPorts, uop->getDecodeSlot());
    if (portPrint_)
      std::cerr << "[SimEng]\t" << std::hex << uop->getInstructionAddress()
                << std::dec << ":" << uop->getSequenceId() << ":"
                << uop->getOpcode() << std::endl;
    uint16_t RS_Index = portMapping_[port].first;
    uint16_t RS_Port = portMapping_[port].second;
    assert(RS_Index < reservationStations_.size() &&
           "Allocated port inaccessible");
    ReservationStation* rs = &reservationStations_[RS_Index];
    // std::cerr << "[SimEng]\t" << uop->getSequenceId() << " Port " << port
    //           << std::endl;

    // std::cerr << "\tDISPATCH: " << std::hex << uop->getInstructionAddress()
    //           << std::dec << ":" << uop->getSequenceId() << std::endl;

    // uint16_t port =
    //     portAllocator_.allocate(supportedPorts, uop->getStallCycles());
    // uint16_t RS_Index = portMapping_[port].first;
    // uint16_t RS_Port = portMapping_[port].second;
    // assert(RS_Index < reservationStations_.size() &&
    //        "Allocated port inaccessible");
    // ReservationStation& rs = reservationStations_[RS_Index];

    auto& sourceRegisters = uop->getOperandRegisters();
    for (uint16_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];

      if (lastDest_.first && lastDest_.second == reg) {  // Reg Match
        if (!(uop->getSupportedPorts().size() < 4 &&
              uop->getSupportedPorts()[0] != 2)) {  // RSX or RSE(EXA,EXB)
          for (const auto& pt : uop->getSupportedPorts()) {
            if (pt == lastPort_) {  // Valid port
              portAllocator_.deallocate(port, uop->getStallCycles());

              port = lastPort_;
              if (portPrint_)
                std::cerr << "[SimEng]\tOverwritten to " << port
                          << " due to dependency" << std::endl;
              RS_Index = portMapping_[port].first;
              RS_Port = portMapping_[port].second;
              assert(RS_Index < reservationStations_.size() &&
                     "Allocated port inaccessible");
              rs = &reservationStations_[RS_Index];
              break;
            }
          }
        }
      }
    }

    // When appropriate, stall uop or input buffer if stall buffer full
    if (rs->currentSize == rs->capacity ||
        dispatches_[RS_Index] == rs->dispatchRate) {
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
    assoicatedIssues_[port]++;

    // Set scoreboard for all destination registers as not ready
    lastDest_ = {false, {0, 0}};
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      // std::cerr << std::hex << uop->getInstructionAddress() << std::dec <<
      // ":"
      //           << uop->getSequenceId() << " - set dest sb "
      //           << unsigned(reg.type) << ":" << reg.tag << std::endl;
      scoreboard_[reg.type][reg.tag] = false;
      if (!(uop->isLoad() || uop->isStoreAddress() || uop->isStoreData())) {
        lastDest_ = {true, reg};
        lastPort_ = port;
      }
    }

    // Increment dispatches made and RS occupied entries size
    dispatches_[RS_Index]++;
    rs->currentSize++;
    uop->setDispatched();

    bool usedTOR = uop->getSupportedPorts()[0] == 6 ? true : false;
    if (print && usedTOR)
      std::cerr << "Early break due to TOR usage " << std::hex
                << uop->getInstructionAddress() << std::dec << " - "
                << uop->getSequenceId() << " - " << uop->getOpcode()
                << std::endl;

    if (ready) {
      if (print)
        std::cerr << "Ready for port " << port << " " << std::hex
                  << uop->getInstructionAddress() << std::dec << " - "
                  << uop->getSequenceId() << " - " << uop->getOpcode()
                  << std::endl;
      rs->ports[RS_Port].ready.push_back(std::move(uop));
    } else {
      if (print)
        std::cerr << "Dependencies registered for port " << port << " "
                  << std::hex << uop->getInstructionAddress() << std::dec
                  << " - " << uop->getSequenceId() << " - " << uop->getOpcode()
                  << std::endl;
    }

    input_.getHeadSlots()[slot] = nullptr;
    if (usedTOR) {
      input_.stall(true);
      lastDest_ = {false, {0, 0}};
      return;
    }
  }
  lastDest_ = {false, {0, 0}};
}

void DispatchIssueUnit::issue() {
  int issued = 0;
  // uint16_t issued5 = false;
  // uint16_t issued6 = false;
  // Check the ready queues, and issue an instruction from each if the
  // corresponding port isn't blocked
  if (issuePrint_) std::cerr << "[SimEng] Issue Queues: [";
  // for (size_t i = 0; i < issuePorts_.size(); i++) {
  //   ReservationStation& rs = reservationStations_[portMapping_[i].first];
  //   auto& queue = rs.ports[portMapping_[i].second].ready;
  //   std::cerr << queue.size() << ",";
  // }
  for (size_t i = 0; i < issuePorts_.size(); i++) {
    ReservationStation& rs = reservationStations_[portMapping_[i].first];
    auto& queue = rs.ports[portMapping_[i].second].ready;
    if (issuePorts_[i].isStalled()) {
      if (queue.size() > 0) {
        backendStallsPort_[i]++;
        portBusyStalls_++;
      }
      // frontendStallsPort_[i]++;
      continue;
    }

    // if (i == 5 | i == 6) {
    //   auto& queue5 = rs.ports[portMapping_[5].second].ready;
    //   auto& queue6 = rs.ports[portMapping_[6].second].ready;
    //   // std::cerr << "Query on " << i << " - " << queue5.size() << "|"
    //   //           << queue6.size() << std::endl;
    //   std::shared_ptr<Instruction> uop = nullptr;
    //   uint16_t chosenQueue = 5;
    //   if (queue5.size() > 0) {
    //     uop = queue5.front();
    //     // std::cerr << "Smth in 5" << std::endl;
    //     // std::cerr << "\t" << uop->getSequenceId() << std::endl;
    //     if (queue6.size() > 0) {
    //       // std::cerr << "Smth in 6" << std::endl;
    //       // std::cerr << "\t" << queue6.front()->getSequenceId() <<
    //       std::endl; if (uop->getSequenceId() >
    //       queue6.front()->getSequenceId()) {
    //         // std::cerr << "6 newer" << std::endl;
    //         uop = queue6.front();
    //         chosenQueue = 6;
    //       } else {
    //         // std::cerr << "6 older" << std::endl;
    //       }
    //     }
    //   } else if (queue6.size() > 0) {
    //     // std::cerr << "Smth in 6" << std::endl;
    //     uop = queue6.front();
    //     chosenQueue = 6;
    //   } else {
    //     // std::cerr << "nothing" << std::endl;
    //     frontendStallsPort_[i]++;
    //     continue;
    //   }

    //   uint16_t chosenPort = chosenQueue;
    //   if (chosenPort == 5 && (issued5 == true ||
    //   issuePorts_[5].isStalled()))
    //   {
    //     chosenPort = 6;
    //   } else if (chosenPort == 6 &&
    //              (issued6 == true || issuePorts_[6].isStalled())) {
    //     chosenPort = 5;
    //   }

    //   if (issuePorts_[chosenPort].isStalled()) {
    //     backendStallsPort_[i]++;
    //     portBusyStalls_++;
    //     continue;
    //   } else if (rs.ports[portMapping_[chosenPort].second].ready.size() ==
    //   0)
    //   {
    //     frontendStallsPort_[i]++;
    //     continue;
    //   }

    //   if (chosenPort == 5) {
    //     issued5 = true;
    //   } else if (chosenPort == 6) {
    //     issued6 = true;
    //   }

    //   std::vector<uint16_t> supportedPorts = uop->getSupportedPorts();
    //   for (const auto& pt : supportedPorts) possibleIssues_[pt]++;
    //   actualIssues_[chosenPort]++;

    //   if (print)
    //     std::cerr << "Issued on port " << chosenPort << " " << std::hex
    //               << uop->getInstructionAddress() << std::dec << " - "
    //               << uop->getSequenceId() << " - " << uop->getOpcode()
    //               << std::endl;

    //   // std::cerr << "\tISSUE: " << std::hex <<
    //   uop->getInstructionAddress()
    //   //           << std::dec << ":" << uop->getSequenceId() << std::endl;

    //   // Inform the port allocator that an instruction issued
    //   portAllocator_.issued(chosenQueue, uop->getStallCycles());
    //   issued++;

    //   issuePorts_[chosenPort].getTailSlots()[0] = std::move(uop);
    //   if (chosenQueue == 5)
    //     queue5.pop_front();
    //   else
    //     queue6.pop_front();

    //   assert(rs.currentSize > 0);
    //   rs.currentSize--;
    // } else {
    bool didIssue = false;
    if (queue.size() > 0) {
      didIssue = true;
      auto& uop = queue.front();

      std::vector<uint16_t> supportedPorts = uop->getSupportedPorts();
      for (const auto& pt : supportedPorts) possibleIssues_[pt]++;
      actualIssues_[i]++;

      if (print)
        std::cerr << "Issued on port " << i << " " << std::hex
                  << uop->getInstructionAddress() << std::dec << " - "
                  << uop->getSequenceId() << " - " << uop->getOpcode()
                  << std::endl;

      // std::cerr << "\tISSUE: " << std::hex << uop->getInstructionAddress()
      //           << std::dec << ":" << uop->getSequenceId() << std::endl;

      // Inform the port allocator that an instruction issued
      assoicatedIssues_[i]--;
      portAllocator_.issued(i, uop->getStallCycles());
      issued++;
      if (issuePrint_)
        std::cerr << std::hex << uop->getInstructionAddress() << std::dec
                  << ",";
      issuePorts_[i].getTailSlots()[0] = std::move(uop);
      queue.pop_front();

      assert(rs.currentSize > 0);
      rs.currentSize--;
    } else if (i == 5) {
      ReservationStation& rs6 = reservationStations_[portMapping_[6].first];
      auto& queue6 = rs6.ports[portMapping_[6].second].ready;
      if (queue6.size() > 1) {
        didIssue = true;
        auto& uop = queue6.front();

        std::vector<uint16_t> supportedPorts = uop->getSupportedPorts();
        for (const auto& pt : supportedPorts) possibleIssues_[pt]++;
        actualIssues_[i]++;

        if (print)
          std::cerr << "Issued on port " << i << " " << std::hex
                    << uop->getInstructionAddress() << std::dec << " - "
                    << uop->getSequenceId() << " - " << uop->getOpcode()
                    << std::endl;

        // std::cerr << "\tISSUE: " << std::hex << uop->getInstructionAddress()
        //           << std::dec << ":" << uop->getSequenceId() << std::endl;

        // Inform the port allocator that an instruction issued
        assoicatedIssues_[i]--;
        portAllocator_.issued(6, uop->getStallCycles());
        issued++;
        if (issuePrint_)
          std::cerr << std::hex << uop->getInstructionAddress() << std::dec
                    << ",";
        issuePorts_[i].getTailSlots()[0] = std::move(uop);
        queue6.pop_front();

        assert(rs6.currentSize > 0);
        rs6.currentSize--;
      } else {
        ReservationStation rs0 = reservationStations_[portMapping_[2].first];
        auto queue2 = rs0.ports[portMapping_[2].second].ready;
        bool compatible = false;
        auto compItr = queue2.begin();
        while (compItr != queue2.end()) {
          if ((*compItr)->getSupportedPorts().size() == 4) {
            compatible = true;
            break;
          }
          compItr++;
        }
        if (!compatible) {
          ReservationStation rs1 = reservationStations_[portMapping_[4].first];
          auto queue4 = rs1.ports[portMapping_[4].second].ready;
          bool compatible = false;
          compItr = queue4.begin();
          while (compItr != queue4.end()) {
            if ((*compItr)->getSupportedPorts().size() == 4) {
              compatible = true;
              break;
            }
            compItr++;
          }
        }
        if (compatible) missedIssues_[i]++;
      }
    } else if (i == 6) {
      ReservationStation& rs5 = reservationStations_[portMapping_[5].first];
      auto& queue5 = rs5.ports[portMapping_[5].second].ready;
      if (queue5.size()) {
        didIssue = true;
        auto& uop = queue5.front();

        std::vector<uint16_t> supportedPorts = uop->getSupportedPorts();
        for (const auto& pt : supportedPorts) possibleIssues_[pt]++;
        actualIssues_[i]++;

        if (print)
          std::cerr << "Issued on port " << i << " " << std::hex
                    << uop->getInstructionAddress() << std::dec << " - "
                    << uop->getSequenceId() << " - " << uop->getOpcode()
                    << std::endl;

        // std::cerr << "\tISSUE: " << std::hex << uop->getInstructionAddress()
        //           << std::dec << ":" << uop->getSequenceId() << std::endl;

        // Inform the port allocator that an instruction issued
        assoicatedIssues_[i]--;
        portAllocator_.issued(5, uop->getStallCycles());
        issued++;
        if (issuePrint_)
          std::cerr << std::hex << uop->getInstructionAddress() << std::dec
                    << ",";
        issuePorts_[i].getTailSlots()[0] = std::move(uop);
        queue5.pop_front();

        assert(rs5.currentSize > 0);
        rs5.currentSize--;
      } else {
        ReservationStation rs0 = reservationStations_[portMapping_[2].first];
        auto queue2 = rs0.ports[portMapping_[2].second].ready;
        bool compatible = false;
        auto compItr = queue2.begin();
        while (compItr != queue2.end()) {
          if ((*compItr)->getSupportedPorts().size() == 4) {
            compatible = true;
            break;
          }
          compItr++;
        }
        if (!compatible) {
          ReservationStation rs1 = reservationStations_[portMapping_[4].first];
          auto queue4 = rs1.ports[portMapping_[4].second].ready;
          bool compatible = false;
          compItr = queue4.begin();
          while (compItr != queue4.end()) {
            if ((*compItr)->getSupportedPorts().size() == 4) {
              compatible = true;
              break;
            }
            compItr++;
          }
        }
        if (compatible) missedIssues_[i]++;
      }
    } else if (i == 0) {
      ReservationStation rs1 = reservationStations_[portMapping_[3].first];
      auto queue3 = rs1.ports[portMapping_[3].second].ready;
      bool compatible = false;
      auto compItr = queue3.begin();
      while (compItr != queue3.end()) {
        if ((*compItr)->getSupportedPorts().size() > 1 &&
            (*compItr)->getSupportedPorts()[0] == 0) {
          compatible = true;
          break;
        }
        compItr++;
      }
      if (compatible) missedIssues_[i]++;
    } else if (i == 3) {
      ReservationStation rs0 = reservationStations_[portMapping_[0].first];
      auto queue0 = rs0.ports[portMapping_[0].second].ready;
      bool compatible = false;
      auto compItr = queue0.begin();
      while (compItr != queue0.end()) {
        if ((*compItr)->getSupportedPorts().size() > 1 &&
            (*compItr)->getSupportedPorts()[1] == 3) {
          compatible = true;
          break;
        }
        compItr++;
      }
      if (compatible) missedIssues_[i]++;
    }

    if (!didIssue) {
      if (issuePrint_) std::cerr << "NA,";
      if (assoicatedIssues_[i] == 0) {
        frontendStallsPort_[i]++;
      } else {
        backendStallsPort_[i]++;
      }
    }
    // }
  }
  if (issuePrint_) std::cerr << "\b]" << std::endl;

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

    scoreboard_[reg.type][reg.tag] = true;

    // Supply the value to all dependent uops
    auto& dependents = dependencyMatrix_[reg.type][reg.tag];
    for (auto& entry : dependents) {
      entry.uop->supplyOperand(entry.operandIndex, values[i]);
      if (entry.uop->canExecute()) {
        // Add the now-ready instruction to the relevant ready queue
        auto rsInfo = portMapping_[entry.port];
        auto rdyItr = reservationStations_[rsInfo.first]
                          .ports[rsInfo.second]
                          .ready.begin();
        while (rdyItr != reservationStations_[rsInfo.first]
                             .ports[rsInfo.second]
                             .ready.end()) {
          if (entry.uop->getSequenceId() < (*rdyItr)->getSequenceId()) break;
          rdyItr++;
        }
        if (print)
          std::cerr << "Forwarded for port " << entry.port << " " << std::hex
                    << entry.uop->getInstructionAddress() << std::dec << " - "
                    << entry.uop->getSequenceId() << " - "
                    << entry.uop->getOpcode() << std::endl;
        reservationStations_[rsInfo.first].ports[rsInfo.second].ready.insert(
            rdyItr, std::move(entry.uop));
      }
    }

    //   // std::cerr << "\t" << std::hex <<
    //   entry.uop->getInstructionAddress()
    //   //           << std::dec << std::endl;
    //   int64_t bypassLatency = operandBypassMap_.getBypassLatency(
    //       producerGroup, entry.uop->getGroup(), reg.type);

    //   // if (entry.uop->getGroup() == 32 && producerGroup == 32) {
    //   //   entry.uop->decLatency(9);
    //   // } else if (entry.uop->getGroup() == 46 && producerGroup == 46) {
    //   //   entry.uop->decLatency(9);
    //   // } else if (entry.uop->getGroup() == 60 && producerGroup == 60) {
    //   //   entry.uop->decLatency(9);
    //   // }

    //   switch (bypassLatency) {
    //     case -1: {
    //       // std::cerr << groupOptions_[producerGroup] << " cannot pass to
    //       "
    //       //           << groupOptions_[entry.uop->getGroup()] << " in port
    //       "
    //       //           << portNames_[entry.port] << std::endl;
    //       // No bypass allowed, add to dependantInstructions_
    //       if (forwardPrint_)
    //         std::cerr << "[SimEng]\t\tAdded to dependent instructions "
    //                   << std::hex << entry.uop->getInstructionAddress()
    //                   << std::dec << " - " << entry.uop->getSequenceId()
    //                   << " - " << entry.uop->getOpcode() << " with group "
    //                   << entry.uop->getGroup() << std::endl;
    //       dependantInstructions_.push_back(entry);
    //       break;
    //     }
    //     case 0: {
    //       // std::cerr << groupOptions_[producerGroup] << " can pass to "
    //       //           << groupOptions_[entry.uop->getGroup()]
    //       //           << " with latency 0 in port " <<
    //       portNames_[entry.port]
    //       //           << std::endl;
    //       // No bypass latency, can supply operand
    //       entry.uop->supplyOperand(entry.operandIndex, values[i]);
    //       if (forwardPrint_)
    //         std::cerr << "[SimEng]\t\tOperand forwarded " << std::hex
    //                   << entry.uop->getInstructionAddress() << std::dec <<
    //                   "
    //                   - "
    //                   << entry.uop->getSequenceId() << " - "
    //                   << entry.uop->getOpcode() << " with group "
    //                   << entry.uop->getGroup() << std::endl;
    //       if (entry.uop->canExecute()) {
    //         if (print)
    //           std::cerr << "[SimEng]\t\tReady for port " << entry.port
    //                     << " in forwardOperands on reg {" <<
    //                     unsigned(reg.type)
    //                     << "," << reg.tag << "} " << std::hex
    //                     << entry.uop->getInstructionAddress() << std::dec
    //                     << " - " << entry.uop->getSequenceId() << " - "
    //                     << entry.uop->getOpcode() << std::endl;
    //         // Add the now-ready instruction to the relevant ready queue
    //         auto rsInfo = portMapping_[entry.port];
    //         // reservationStations_[rsInfo.first]
    //         //     .ports[rsInfo.second]
    //         //     .ready.push_front(std::move(entry.uop));
    //         bool inserted = false;
    //         if (reservationStations_[rsInfo.first]
    //                 .ports[rsInfo.second]
    //                 .ready.size()) {
    //           auto itEntry = reservationStations_[rsInfo.first]
    //                              .ports[rsInfo.second]
    //                              .ready.begin();
    //           while (itEntry != reservationStations_[rsInfo.first]
    //                                 .ports[rsInfo.second]
    //                                 .ready.end()) {
    //             if ((*itEntry)->getSequenceId() >
    //             entry.uop->getSequenceId())
    //             {
    //               reservationStations_[rsInfo.first]
    //                   .ports[rsInfo.second]
    //                   .ready.insert(itEntry, std::move(entry.uop));
    //               inserted = true;
    //               break;
    //             }
    //             itEntry++;
    //           }
    //         }
    //         if (!inserted)
    //           reservationStations_[rsInfo.first]
    //               .ports[rsInfo.second]
    //               .ready.push_back(std::move(entry.uop));
    //       }
    //       break;
    //     }
    //     default: {
    //       // std::cerr << groupOptions_[producerGroup] << " can pass to "
    //       //           << groupOptions_[entry.uop->getGroup()] << " with
    //       latency
    //       //           "
    //       //           << bypassLatency << " in port " <<
    //       portNames_[entry.port]
    //       //           << std::endl;
    //       // Some bypass latency to adhear to, add to waitingInstructions_
    //       assert(bypassLatency > 0 &&
    //              "Negative bypass latency other than -1 is not valid.");
    //       uint64_t releaseOnTick = ticks_ + bypassLatency;
    //       if (forwardPrint_)
    //         std::cerr << "[SimEng]\t\tAdded to waiting instructions until "
    //                   << releaseOnTick << " - " << std::hex
    //                   << entry.uop->getInstructionAddress() << std::dec <<
    //                   "
    //                   - "
    //                   << entry.uop->getSequenceId() << " - "
    //                   << entry.uop->getOpcode() << " with group "
    //                   << entry.uop->getGroup() << std::endl;
    //       // Make vector containing new entry
    //       std::vector<std::pair<dependencyEntry, RegisterValue>> vec = {
    //           std::make_pair(entry, values[i])};
    //       // If entries for this tick already exist, then add these to the
    //       new
    //       // vector
    //       if (waitingInstructions_.find(releaseOnTick) !=
    //           waitingInstructions_.end()) {
    //         vec.insert(vec.end(),
    //         waitingInstructions_[releaseOnTick].begin(),
    //                    waitingInstructions_[releaseOnTick].end());
    //       }
    //       waitingInstructions_[releaseOnTick] = vec;
    //       break;
    //     }
    //   }
    // }
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
          assoicatedIssues_[port.issuePort]--;
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
            assoicatedIssues_[entry.port]--;
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
        assoicatedIssues_[itDepInsn->port]--;
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
          assoicatedIssues_[depEntry.port]--;
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
  uint8_t idx = 0;
  for (auto& rs : reservationStations_) {
    sizes[idx] = (rs.capacity - rs.currentSize);
    idx++;
  }
}

void DispatchIssueUnit::updateScoreboard(const Register& reg,
                                         const RegisterValue& val) {
  scoreboard_[reg.type][reg.tag] = true;
  std::vector<dependencyEntry> readyInsns;

  auto itDep = dependantInstructions_.begin();
  while (itDep != dependantInstructions_.end()) {
    const auto& reg = itDep->uop->getOperandRegisters()[itDep->operandIndex];
    if (scoreboard_[reg.type][reg.tag]) {
      // The scoreboard says it's ready; read and supply the register value
      itDep->uop->supplyOperand(itDep->operandIndex, registerFileSet_.get(reg));
      if (itDep->uop->canExecute()) {
        readyInsns.push_back(*itDep);
        // std::cerr << "Ready for port " << itDep->port
        //           << " in dependantInstructions_ " << std::hex
        //           << itDep->uop->getInstructionAddress() << std::dec << " -
        //           "
        //           << itDep->uop->getSequenceId() << " - "
        //           << itDep->uop->getOpcode() << std::endl;
        // Add the now-ready instruction to the relevant ready queue
        // auto rsInfo = portMapping_[itDep->port];
        // reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_front(
        //     std::move(itDep->uop));
      }
      itDep = dependantInstructions_.erase(itDep);
    } else {
      itDep++;
    }
  }

  auto& dependents = dependencyMatrix_[reg.type][reg.tag];
  for (auto& entry : dependents) {  // No bypass latency, can supply operand
    entry.uop->supplyOperand(entry.operandIndex, val);
    if (entry.uop->canExecute()) {
      readyInsns.push_back(entry);
      // std::cerr << "Ready for port " << entry.port << " in updateScoreboard
      // "
      //           << std::hex << entry.uop->getInstructionAddress() <<
      //           std::dec
      //           << " - " << entry.uop->getSequenceId() << " - "
      //           << entry.uop->getOpcode() << std::endl;
      // Add the now-ready instruction to the relevant ready queue
      // auto rsInfo = portMapping_[entry.port];
      // reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_front(
      //     std::move(entry.uop));
    }
  }

  for (auto& depEntry : readyInsns) {
    auto rsInfo = portMapping_[depEntry.port];
    if (print)
      std::cerr << "Ready for port " << depEntry.port << " in updateScoreboard "
                << std::hex << depEntry.uop->getInstructionAddress() << std::dec
                << " - " << depEntry.uop->getSequenceId() << " - "
                << depEntry.uop->getOpcode() << std::endl;
    // reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_front(
    //     std::move(depEntry.uop));

    bool inserted = false;
    if (reservationStations_[rsInfo.first].ports[rsInfo.second].ready.size()) {
      auto itEntry =
          reservationStations_[rsInfo.first].ports[rsInfo.second].ready.begin();
      while (
          itEntry !=
          reservationStations_[rsInfo.first].ports[rsInfo.second].ready.end()) {
        if ((*itEntry)->getSequenceId() > depEntry.uop->getSequenceId()) {
          reservationStations_[rsInfo.first].ports[rsInfo.second].ready.insert(
              itEntry, std::move(depEntry.uop));
          inserted = true;
          break;
        }
        itEntry++;
      }
    }
    if (!inserted)
      reservationStations_[rsInfo.first].ports[rsInfo.second].ready.push_back(
          std::move(depEntry.uop));
  }
  readyInsns.clear();

  // Clear the dependency list
  dependencyMatrix_[reg.type][reg.tag].clear();
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
const std::vector<uint64_t> DispatchIssueUnit::getMissedIssues() const {
  return missedIssues_;
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
