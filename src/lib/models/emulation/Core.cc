#include "simeng/models/emulation/Core.hh"

#include <cstring>

namespace simeng {
namespace models {
namespace emulation {

// TODO: Expose as config option
/** The number of bytes fetched each cycle. */
const uint8_t FETCH_SIZE = 4;
const unsigned int clockFrequency = 2.5 * 1e9;

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           uint64_t entryPoint, uint64_t programByteLength,
           const arch::Architecture& isa)
    : instructionMemory_(instructionMemory),
      dataMemory_(dataMemory),
      programByteLength_(programByteLength),
      isa_(isa),
      pc_(entryPoint),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_) {
  // Pre-load the first instruction
  instructionMemory_.requestRead({pc_, FETCH_SIZE});

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
}

void Core::tick() {
  ticks_++;

  if (pc_ >= programByteLength_) {
    hasHalted_ = true;
    return;
  }

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  if (pendingReads_ > 0) {
    // Handle pending reads to a uop
    auto& uop = microOps_.front();

    const auto& completedReads = dataMemory_.getCompletedReads();
    for (const auto& response : completedReads) {
      assert(pendingReads_ > 0);
      uop->supplyData(response.target.address, response.data);
      pendingReads_--;
    }
    dataMemory_.clearCompletedReads();

    if (pendingReads_ == 0) {
      // Load complete: resume execution
      execute(uop);
    }

    // More data pending, end cycle early
    return;
  }

  // Fetch

  // Determine if new uops are needed to be fetched
  if (!microOps_.size()) {
    // Find fetched memory that matches the current PC
    const auto& fetched = instructionMemory_.getCompletedReads();
    size_t fetchIndex;
    for (fetchIndex = 0; fetchIndex < fetched.size(); fetchIndex++) {
      if (fetched[fetchIndex].target.address == pc_) {
        break;
      }
    }
    if (fetchIndex == fetched.size()) {
      // Need to wait for fetched instructions
      return;
    }

    const auto& instructionBytes = fetched[fetchIndex].data;
    auto bytesRead = isa_.predecode(instructionBytes.getAsVector<char>(),
                                    FETCH_SIZE, pc_, {false, 0}, macroOp_);

    // Clear the fetched data
    instructionMemory_.clearCompletedReads();

    pc_ += bytesRead;

    // Decode
    for (size_t index = 0; index < macroOp_.size(); index++) {
      microOps_.push(std::move(macroOp_[index]));
    }
  }

  auto& uop = microOps_.front();

  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  // Issue
  auto registers = uop->getOperandRegisters();
  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(i, registerFileSet_.get(reg));
    }
  }

  // Execute
  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    previousAddresses_.clear();
    if (uop->exceptionEncountered()) {
      handleException(uop);
      return;
    }
    if (addresses.size() > 0) {
      // Memory reads are required; request them, set `pendingReads_`
      // accordingly, and end the cycle early
      for (auto const& target : addresses) {
        // std::cout << "\tLoad: 0x" << std::hex << uop->getInstructionAddress()
        //           << std::dec << ":0x" << std::hex << target.address <<
        //           std::dec
        //           << std::endl;
        dataMemory_.requestRead(target);
        // Store addresses for use by next store data operation
        previousAddresses_.push_back(target);
      }
      pendingReads_ = addresses.size();
      return;
    } else {
      // Early execution due to lacking addresses
      execute(uop);
      return;
    }
  } else if (uop->isStoreAddress()) {
    auto addresses = uop->generateAddresses();
    previousAddresses_.clear();
    if (uop->exceptionEncountered()) {
      handleException(uop);
      return;
    }
    // Store addresses for use by next store data operation
    for (auto const& target : addresses) {
      previousAddresses_.push_back(target);
    }
    if (uop->isStoreData()) {
      execute(uop);
    } else {
      // Fetch memory for next cycle
      instructionMemory_.requestRead({pc_, FETCH_SIZE});
      microOps_.pop();
    }

    return;
  }

  execute(uop);
}

void Core::execute(std::shared_ptr<Instruction>& uop) {
  uop->execute();

  if (uop->exceptionEncountered()) {
    handleException(uop);
    return;
  }

  if (uop->isStoreData()) {
    auto results = uop->getResults();
    auto destinations = uop->getDestinationRegisters();
    // std::cout << "WB: 0x" << std::hex << uop->getInstructionAddress()
    //           << std::dec << std::endl;
    // for (size_t i = 0; i < results.size(); i++) {
    //   // Write results to register file
    //   std::cout << "\t" << unsigned(destinations[i].type) << ":"
    //             << unsigned(destinations[i].tag) << " <- ";
    //   if (results[i].size() == 1)
    //     std::cout << unsigned(results[i].get<uint8_t>());
    //   else if (results[i].size() == 2)
    //     std::cout << results[i].get<uint16_t>();
    //   else if (results[i].size() == 4)
    //     std::cout << results[i].get<uint32_t>();
    //   else if (results[i].size() == 8)
    //     std::cout << results[i].get<uint64_t>();
    //   else if (results[i].size() == 256)
    //     std::cout << results[i].getAsVector<uint64_t>()[0] << ":"
    //               << results[i].getAsVector<uint64_t>()[1];
    //   else
    //     std::cout << "N/A";
    //   std::cout << std::endl;
    // }
    auto data = uop->getData();
    for (size_t i = 0; i < previousAddresses_.size(); i++) {
      // std::cout << "\tStore: 0x" << std::hex << uop->getInstructionAddress()
      //           << std::dec << ":0x" << std::hex
      //           << previousAddresses_[i].address << std::dec << " <- ";
      // if (data[i].size() == 1)
      //   std::cout << unsigned(data[i].get<uint8_t>());
      // else if (data[i].size() == 2)
      //   std::cout << data[i].get<uint16_t>();
      // else if (data[i].size() == 4)
      //   std::cout << data[i].get<uint32_t>();
      // else if (data[i].size() == 8)
      //   std::cout << data[i].get<uint64_t>();
      // else if (data[i].size() == 256)
      //   std::cout << data[i].getAsVector<uint64_t>()[0] << ":"
      //             << data[i].getAsVector<uint64_t>()[1];
      // else
      //   std::cout << "N/A";
      // std::cout << std::endl;
      dataMemory_.requestWrite(previousAddresses_[i], data[i]);
    }
  } else if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();
    branchesExecuted_++;
  }

  // Writeback
  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  if (uop->isStoreData()) {
    for (size_t i = 0; i < results.size(); i++) {
      auto reg = destinations[i];
      registerFileSet_.set(reg, results[i]);
    }
  } else {
    // std::cout << "WB: 0x" << std::hex << uop->getInstructionAddress()
    //           << std::dec << std::endl;
    for (size_t i = 0; i < results.size(); i++) {
      auto reg = destinations[i];
      registerFileSet_.set(reg, results[i]);
      // Write results to register file
      // std::cout << "\t" << unsigned(destinations[i].type) << ":"
      //           << unsigned(destinations[i].tag) << " <- ";
      // if (results[i].size() == 1)
      //   std::cout << unsigned(results[i].get<uint8_t>());
      // else if (results[i].size() == 2)
      //   std::cout << results[i].get<uint16_t>();
      // else if (results[i].size() == 4)
      //   std::cout << results[i].get<uint32_t>();
      // else if (results[i].size() == 8)
      //   std::cout << results[i].get<uint64_t>();
      // else if (results[i].size() == 256)
      //   std::cout << results[i].getAsVector<uint64_t>()[0] << ":"
      //             << results[i].getAsVector<uint64_t>()[1];
      // else
      //   std::cout << "N/A";
      // std::cout << std::endl;
    }
  }

  if (uop->isLastMicroOp()) instructionsExecuted_++;
  // std::cout << std::hex << uop->getInstructionAddress() << std::dec
  //           << std::endl;

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
  microOps_.pop();
}

void Core::handleException(const std::shared_ptr<Instruction>& instruction) {
  exceptionHandler_ = isa_.handleException(instruction, *this, dataMemory_);
  processExceptionHandler();
}

void Core::processExceptionHandler() {
  assert(exceptionHandler_ != nullptr &&
         "Attempted to process an exception handler that wasn't present");

  bool success = exceptionHandler_->tick();

  if (!success) {
    // Handler needs further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    pc_ = programByteLength_;
    hasHalted_ = true;
    std::cout << "Halting due to fatal exception" << std::endl;
  } else {
    pc_ = result.instructionAddress;
    applyStateChange(result.stateChange);
  }

  // std::cout << "WB: 0x" << std::hex << result.instructionAddress - 4 <<
  // std::dec
  //           << std::endl;

  // Clear the handler
  exceptionHandler_ = nullptr;

  // Fetch memory for next cycle
  instructionMemory_.requestRead({pc_, FETCH_SIZE});
  microOps_.pop();
}

void Core::applyStateChange(const arch::ProcessStateChange& change) {
  // Update registers
  for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
    registerFileSet_.set(change.modifiedRegisters[i],
                         change.modifiedRegisterValues[i]);
  }

  // Update memory
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    dataMemory_.requestWrite(change.memoryAddresses[i],
                             change.memoryAddressValues[i]);
  }
}

bool Core::hasHalted() const { return hasHalted_; }

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return instructionsExecuted_;
}

uint64_t Core::getSystemTimer() const {
  return ticks_ / (clockFrequency / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  return {{"instructions", std::to_string(instructionsExecuted_)},
          {"branch.executed", std::to_string(branchesExecuted_)}};
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
