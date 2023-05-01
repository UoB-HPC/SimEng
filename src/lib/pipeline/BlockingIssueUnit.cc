#include "simeng/pipeline/BlockingIssueUnit.hh"

#include <algorithm>
#include <iostream>

namespace simeng {
namespace pipeline {

BlockingIssueUnit::BlockingIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& input,
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& issuePorts,
    PortAllocator& portAllocator,
    std::function<void(const std::shared_ptr<Instruction>&)> recordIssue,
    LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    const RegisterFileSet& registerFileSet,
    const std::vector<uint16_t>& physicalRegisterStructure)
    : input_(input),
      issuePorts_(issuePorts),
      portAllocator_(portAllocator),
      scoreboard_(physicalRegisterStructure.size()),
      recordIssue_(recordIssue),
      lsq_(lsq),
      raiseException_(raiseException),
      registerFileSet_(registerFileSet) {
  YAML::Node& config = Config::get();
  // Initialise scoreboard
  for (size_t type = 0; type < physicalRegisterStructure.size(); type++) {
    scoreboard_[type].assign(physicalRegisterStructure[type], {true, -1});
  }
}

void BlockingIssueUnit::tick() {
  input_.stall(false);

  int issued = 0;

  // Iterate over the input buffer and add uops to the issue queue
  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& uop = input_.getHeadSlots()[slot];
    if (uop == nullptr) {
      continue;
    }

    // If the size of the input queue is greater than the number of ports, stall
    // input to avoid over supply to the issue unit
    if (issueQueue_.size() < issuePorts_.size()) {
      issueQueue_.push_back(std::move(uop));
      input_.getHeadSlots()[slot] = nullptr;
    } else {
      input_.stall(true);
    }
  }

  while (issueQueue_.size()) {
    auto& uop = issueQueue_.front();
    bool ready = true;

    // If a instruction has an exception to raise, record its issue but omit
    // from sending to an exceution unit as it would be unsafe
    if (uop->exceptionEncountered()) {
      recordIssue_(uop);
      raiseException_(uop);
      issueQueue_.pop_front();
      continue;
    }

    // Register read
    // Identify remaining missing registers and supply values
    auto& sourceRegisters = uop->getOperandRegisters();
    for (uint16_t i = 0; i < sourceRegisters.size(); i++) {
      const auto& reg = sourceRegisters[i];

      if (!uop->isOperandReady(i)) {
        // The operand hasn't already been supplied
        if (scoreboard_[reg.type][reg.tag].first) {
          // The scoreboard says it's ready; read and supply the register value
          uop->supplyOperand(i, registerFileSet_.get(reg));
        } else {
          // This register isn't ready yet. Stall the unit until the scoreboard
          // bit is released
          input_.stall(true);
          ready = false;
          dependent_ = true;
          dependency_ = {reg, i};
          break;
        }
      }
    }

    // Check if all destination registers are ready in the scoreboard to enfore
    // WAW dependencies
    auto& destinationRegisters = uop->getDestinationRegisters();
    for (const auto& reg : destinationRegisters) {
      if (!scoreboard_[reg.type][reg.tag].first) {
        input_.stall(true);
        ready = false;
        break;
      }
    }

    // Allocate issue port to uop
    uint16_t port = portAllocator_.allocate(uop->getSupportedPorts());

    // If the issue port has already been issued to this cycle, break and
    // continue issue next cycle
    if (issuePorts_[port].getTailSlots()[0] != nullptr) {
      input_.stall(true);
      portBusyStalls_++;
      ready = false;
    }

    if (!ready) {
      // Deallocate port if uop is not ready to issue
      portAllocator_.deallocate(port);
      break;
    }

    // Clear any dependencies for this uop
    dependent_ = false;
    dependency_ = {};

    // Set scoreboard for all destination registers as not ready
    for (const auto& reg : destinationRegisters) {
      scoreboard_[reg.type][reg.tag] = {false, uop->getSequenceId()};
    }

    // Record that this uop has been issue and send to an execution unit through
    // allocated port
    recordIssue_(uop);

    if (uop->isLoad()) {
      lsq_.addLoad(uop);
    }
    if (uop->isStoreAddress()) {
      lsq_.addStore(uop);
    }

    issuePorts_[port].getTailSlots()[0] = std::move(uop);
    portAllocator_.issued(port);

    issueQueue_.pop_front();
    issued++;
  }

  // Record reasoning for zero issuing this cycle
  if (issued == 0) {
    if (input_.isStalled())
      backendStalls_++;
    else
      frontendStalls_++;
  }
}

void BlockingIssueUnit::forwardOperands(const span<Register>& registers,
                                        const span<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

  for (size_t i = 0; i < registers.size(); i++) {
    const auto& reg = registers[i];
    // If the forwarded register is one depended on, supply value to uop at
    // front of issue queue
    if (dependent_ && reg == dependency_.first) {
      auto& uop = issueQueue_.front();
      uop->supplyOperand(dependency_.second, values[i]);
      assert(uop->getSequenceId() == issueQueue_.front()->getSequenceId() &&
             "Tried to early issue uop not at front of queue");
      // If the uop is now ready to execute, identify whether it can be issued
      // to avoid pipeline bubbles
      if (issueQueue_.front()->canExecute()) {
        bool ready = true;

        // Allocate issue port to uop
        uint16_t port = portAllocator_.allocate(uop->getSupportedPorts());

        // Query whether port is free
        if (issuePorts_[port].getTailSlots()[0] == nullptr) {
          auto& destinationRegisters = uop->getDestinationRegisters();
          // Query whether the destination registers are ready
          for (const auto& reg : destinationRegisters) {
            if (!scoreboard_[reg.type][reg.tag].first) {
              ready = false;
              break;
            }
          }
        } else {
          ready = false;
        }

        // Issue the uop if all required resources are available, else
        // deallocate the port
        if (ready) {
          auto& destinationRegisters = uop->getDestinationRegisters();
          for (const auto& reg : destinationRegisters) {
            scoreboard_[reg.type][reg.tag] = {false, uop->getSequenceId()};
          }

          recordIssue_(uop);

          if (uop->isLoad()) {
            lsq_.addLoad(uop);
          }
          if (uop->isStoreAddress()) {
            lsq_.addStore(uop);
          }

          issuePorts_[port].getTailSlots()[0] = std::move(uop);
          portAllocator_.issued(port);

          issueQueue_.pop_front();
          input_.stall(false);
        } else {
          portAllocator_.deallocate(port);
        }
      }

      dependent_ = false;
      dependency_ = {};
      break;
    }
  }
}

void BlockingIssueUnit::setRegisterReady(Register reg) {
  scoreboard_[reg.type][reg.tag] = {true, -1};
}

uint64_t BlockingIssueUnit::getFrontendStalls() const {
  return frontendStalls_;
}
uint64_t BlockingIssueUnit::getBackendStalls() const { return backendStalls_; }
uint64_t BlockingIssueUnit::getPortBusyStalls() const {
  return portBusyStalls_;
}

void BlockingIssueUnit::flush(uint64_t afterSeqId) {
  // Set scoreboard entries as ready if they were set as unready by a newer
  // instruction than the sequence ID passed
  for (size_t i = 0; i < scoreboard_.size(); i++) {
    for (size_t j = 0; j < scoreboard_[i].size(); j++) {
      if (scoreboard_[i][j].second > afterSeqId) {
        scoreboard_[i][j] = {true, -1};
      }
    }
  }

  // Clear any dependency and the issue queue as the assocaited instructions are
  // guaranteed to be newer in the program-order
  dependent_ = false;
  dependency_ = {};
  issueQueue_.clear();
}

void BlockingIssueUnit::flush() {
  // Set all registers as ready in the scoreboard
  for (size_t i = 0; i < scoreboard_.size(); i++) {
    for (size_t j = 0; j < scoreboard_[i].size(); j++) {
      scoreboard_[i][j] = {true, -1};
    }
  }

  // Clear any dependency and the issue queue as the assocaited instructions are
  // guaranteed to be newer in the program-order
  dependent_ = false;
  dependency_ = {};
  issueQueue_.clear();
}

}  // namespace pipeline
}  // namespace simeng
