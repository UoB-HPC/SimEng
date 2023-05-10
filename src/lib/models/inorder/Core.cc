#include "simeng/models/inorder/Core.hh"

#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

namespace simeng {
namespace models {
namespace inorder {

Core::Core(const arch::Architecture& isa, BranchPredictor& branchPredictor,
           std::shared_ptr<memory::MMU> mmu,
           pipeline::PortAllocator& portAllocator,
           arch::sendSyscallToHandler handleSyscall, YAML::Node& config)
    : mmu_(mmu),
      isa_(isa),
      registerFileSet_(isa.getRegisterFileStructures()),
      architecturalRegisterFileSet_(registerFileSet_),
      fetchToDecodeBuffer_(1, {}),
      decodeToIssueBuffer_(1, nullptr),
      issuePorts_(config["Execution-Units"].size(), {1, nullptr}),
      completionSlots_(
          config["Execution-Units"].size() +
              config["Pipeline-Widths"]["LSQ-Completion"].as<unsigned int>(),
          {1, nullptr}),
      loadStoreQueue_(
          config["Queue-Sizes"]["Load"].as<unsigned int>(),
          config["Queue-Sizes"]["Store"].as<unsigned int>(), mmu_,
          {completionSlots_.data() + config["Execution-Units"].size(),
           config["Pipeline-Widths"]["LSQ-Completion"].as<unsigned int>()},
          [this](auto regs, auto values) {
            issueUnit_.forwardOperands(regs, values);
          },
          simeng::pipeline::completionOrder::INORDER,
          config["LSQ-Memory-Interface"]["Exclusive"].as<bool>(),
          config["LSQ-Memory-Interface"]["Load-Bandwidth"].as<uint16_t>(),
          config["LSQ-Memory-Interface"]["Store-Bandwidth"].as<uint16_t>(),
          config["LSQ-Memory-Interface"]["Permitted-Requests-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-Memory-Interface"]["Permitted-Loads-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-Memory-Interface"]["Permitted-Stores-Per-Cycle"]
              .as<uint16_t>()),
      fetchUnit_(fetchToDecodeBuffer_, mmu_,
                 config["Fetch"]["Fetch-Block-Size"].as<uint16_t>(), isa,
                 branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToIssueBuffer_, branchPredictor),
      staging_(),
      issueUnit_(
          decodeToIssueBuffer_, issuePorts_, portAllocator,
          [this](auto insn) { staging_.recordIssue(insn); }, loadStoreQueue_,
          [this](auto insn) { raiseException(insn); }, registerFileSet_,
          isa.getConfigPhysicalRegisterQuantities()),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto reg) { issueUnit_.setRegisterReady(reg); },
          [this](auto seqId) { return staging_.canWriteback(seqId); },
          [this](auto insn) { retireInstruction(insn); }),
      portAllocator_(portAllocator),
      handleSyscall_(handleSyscall) {
  for (size_t i = 0; i < config["Execution-Units"].size(); i++) {
    // Create vector of blocking groups
    std::vector<uint16_t> blockingGroups = {};
    if (config["Execution-Units"][i]["Blocking-Groups"].IsDefined()) {
      for (YAML::Node gp : config["Execution-Units"][i]["Blocking-Groups"]) {
        blockingGroups.push_back(gp.as<uint16_t>());
      }
    }
    executionUnits_.emplace_back(
        issuePorts_[i], completionSlots_[i],
        [this](auto regs, auto values) {
          issueUnit_.forwardOperands(regs, values);
        },
        [this](auto insn) { handleLoad(insn); },
        [this](auto insn) { storeData(insn); },
        [this](auto insn) { raiseException(insn); }, branchPredictor,
        config["Execution-Units"][i]["Pipelined"].as<bool>(), blockingGroups);
  }
  // Create exception handler based on chosen architecture
  exceptionHandlerFactory(Config::get()["Core"]["ISA"].as<std::string>());
}

void Core::tick() {
  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

  switch (status_) {
    case CoreStatus::idle:
      idle_ticks_++;
      return;
    case CoreStatus::switching: {
      // Ensure the pipeline is empty and there's no active exception before
      // context switching.
      if (fetchToDecodeBuffer_.isEmpty() && decodeToIssueBuffer_.isEmpty() &&
          staging_.isEmpty() && !mmu_->hasPendingRequests() &&
          (exceptionGenerated_ == false)) {
        // Flush pipeline
        fetchUnit_.flushLoopBuffer();
        decodeUnit_.purgeFlushed();
        issueUnit_.flush();
        staging_.flush();
        for (auto& eu : executionUnits_) {
          eu.flush();
        }
        status_ = CoreStatus::idle;
        return;
      }
      break;
    }
    case CoreStatus::halted:
      return;
    default:
      break;
  }

  // Increase tick count for current process execution
  procTicks_++;

  if (exceptionRegistered_) {
    processException();
    return;
  }

  // Tick port allocator's internal functionality at start of cycle
  portAllocator_.tick();

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();

  // Tick units
  fetchUnit_.tick();
  decodeUnit_.tick();
  issueUnit_.tick();
  for (auto& eu : executionUnits_) {
    eu.tick();
  }
  loadStoreQueue_.tick();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after
  // use, as these will now loop around and become the tail.
  fetchToDecodeBuffer_.tick();
  decodeToIssueBuffer_.tick();
  for (auto& buffer : issuePorts_) {
    buffer.tick();
  }
  for (auto& buffer : completionSlots_) {
    buffer.tick();
  }

  if (exceptionGenerated_ && handleException()) {
    fetchUnit_.requestFromPC();
    return;
  }

  flushIfNeeded();
  fetchUnit_.requestFromPC();
}

void Core::flushIfNeeded() {
  // Check for flush
  bool euFlush = false;
  uint64_t targetAddress = 0;
  uint64_t lowestSeqId = 0;
  for (const auto& eu : executionUnits_) {
    if (eu.shouldFlush() && (!euFlush || eu.getFlushSeqId() < lowestSeqId)) {
      euFlush = true;
      lowestSeqId = eu.getFlushSeqId();
      targetAddress = eu.getFlushAddress();
    }
  }
  if (euFlush) {
    // Flush was requested at execute stage
    // Update PC and wipe pipeline buffers/units

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    decodeUnit_.purgeFlushed();
    decodeToIssueBuffer_.fill(nullptr);
    issueUnit_.flush(lowestSeqId);
    staging_.flush(lowestSeqId);
    for (auto& eu : executionUnits_) {
      eu.purgeFlushed();
    }
    loadStoreQueue_.purgeFlushed();

    // Given instructions can flow out-of-order during execution due to
    // differing latencies, the issue ports need to be cleared conditionally
    // based on the sequence IDs
    for (auto& port : issuePorts_) {
      if (port.getHeadSlots()[0] != nullptr &&
          port.getHeadSlots()[0]->getSequenceId() > lowestSeqId)
        port.getHeadSlots()[0] = nullptr;
      if (port.getTailSlots()[0] != nullptr &&
          port.getTailSlots()[0]->getSequenceId() > lowestSeqId)
        port.getTailSlots()[0] = nullptr;
    }

    // Given instructions can flow out-of-order during execution due to
    // differing latencies, the completion slots need to be cleared
    // conditionally based on the sequence IDs
    for (auto& slot : completionSlots_) {
      if (slot.getHeadSlots()[0] != nullptr &&
          slot.getHeadSlots()[0]->getSequenceId() > lowestSeqId)
        slot.getHeadSlots()[0] = nullptr;
      if (slot.getTailSlots()[0] != nullptr &&
          slot.getTailSlots()[0]->getSequenceId() > lowestSeqId)
        slot.getTailSlots()[0] = nullptr;
    }

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

    flushes_++;
  }
}

CoreStatus Core::getStatus() { return status_; }

void Core::setStatus(CoreStatus newStatus) { status_ = newStatus; }

uint64_t Core::getCurrentTID() const { return currentTID_; }

uint64_t Core::getCoreId() const { return coreId_; }

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return architecturalRegisterFileSet_;
}

void Core::sendSyscall(OS::SyscallInfo syscallInfo) const {
  handleSyscall_(syscallInfo);
}

void Core::receiveSyscallResult(const OS::SyscallResult result) const {
  exceptionHandler_->processSyscallResult(result);
}

uint64_t Core::getInstructionsRetiredCount() const {
  return writebackUnit_.getInstructionsWrittenCount();
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit_.getInstructionsWrittenCount();
  auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  auto branchStalls = fetchUnit_.getBranchStalls();

  auto earlyFlushes = decodeUnit_.getEarlyFlushes();

  auto frontendStalls = issueUnit_.getFrontendStalls();
  auto backendStalls = issueUnit_.getBackendStalls();
  auto portBusyStalls = issueUnit_.getPortBusyStalls();

  // Sum up the branch stats reported across the execution units.
  uint64_t totalBranchesExecuted = 0;
  uint64_t totalBranchMispredicts = 0;
  for (auto& eu : executionUnits_) {
    totalBranchesExecuted += eu.getBranchExecutedCount();
    totalBranchMispredicts += eu.getBranchMispredictedCount();
  }
  auto branchMissRate = 100.0f * static_cast<float>(totalBranchMispredicts) /
                        static_cast<float>(totalBranchesExecuted);
  std::ostringstream branchMissRateStr;
  branchMissRateStr << std::setprecision(3) << branchMissRate << "%";

  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(retired)},
          {"ipc", ipcStr.str()},
          {"flushes", std::to_string(flushes_)},
          {"fetch.branchStalls", std::to_string(branchStalls)},
          {"decode.earlyFlushes", std::to_string(earlyFlushes)},
          {"branch.executed", std::to_string(totalBranchesExecuted)},
          {"branch.mispredict", std::to_string(totalBranchMispredicts)},
          {"issue.frontendStalls", std::to_string(frontendStalls)},
          {"issue.backendStalls", std::to_string(backendStalls)},
          {"issue.portBusyStalls", std::to_string(portBusyStalls)},
          {"branch.executed", std::to_string(totalBranchesExecuted)},
          {"branch.mispredict", std::to_string(totalBranchMispredicts)},
          {"branch.missrate", branchMissRateStr.str()},
          {"idle.ticks", std::to_string(idle_ticks_)},
          {"context.switches", std::to_string(contextSwitches_)}};
}

void Core::raiseException(const std::shared_ptr<Instruction>& insn) {
  // If an exception has already been generated by the pipeline, only replace
  // the exceptionGeneratingInstruction_ if the passed instruction is younger
  if (exceptionGenerated_) {
    if (exceptionGeneratingInstruction_->getSequenceId() <
        insn->getSequenceId()) {
      return;
    }
  }
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = insn;
}

bool Core::handleException() {
  // Only handle the generated exception if the associated instruction is the
  // next one to be written back
  if (exceptionGeneratingInstruction_->getSequenceId() > staging_.getNextId())
    return false;

  exceptionHandler_->registerException(exceptionGeneratingInstruction_);
  exceptionRegistered_ = true;
  processException();

  // Flush pipeline
  fetchUnit_.flushLoopBuffer();
  fetchToDecodeBuffer_.fill({});
  decodeToIssueBuffer_.fill(nullptr);
  decodeUnit_.purgeFlushed();
  issueUnit_.flush();
  staging_.flush();
  for (auto& eu : executionUnits_) {
    eu.flush();
  }
  loadStoreQueue_.purgeFlushed();
  for (auto& buffer : issuePorts_) {
    buffer.fill(nullptr);
  }
  for (auto& buffer : completionSlots_) {
    buffer.fill(nullptr);
  }
  return true;
}

void Core::processException() {
  assert(exceptionRegistered_ != false &&
         "[SimEng:Core] Attempted to process an exception which wasn't "
         "registered with the handler");
  if (mmu_->hasPendingRequests()) {
    // Must wait for all memory requests to complete before processing the
    // exception
    return;
  }

  auto success = exceptionHandler_->tick();
  if (!success) {
    // Exception handler requires further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    status_ = CoreStatus::halted;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
    if (result.idleAfterSyscall) {
      // Update core status
      status_ = CoreStatus::idle;
      contextSwitches_++;
    }
  }

  exceptionGenerated_ = false;
  exceptionRegistered_ = false;
}

void Core::handleLoad(const std::shared_ptr<Instruction>& insn) {
  // Start the load in the LSQ
  loadStoreQueue_.startLoad(insn);
}

void Core::storeData(const std::shared_ptr<Instruction>& insn) {
  // Supply the data to be stored to the recently added store address uop
  // within the LSQ (a check for whether the passed instruction is/contains a
  // store data uop is done within the supplyStoreData call)
  loadStoreQueue_.supplyStoreData(insn);
}

void Core::retireInstruction(const std::shared_ptr<Instruction>& insn) {
  // Raise an exception if the recently written back instruction has generated
  // one
  if (insn->exceptionEncountered()) {
    raiseException(insn);
    staging_.recordRetired(insn->getSequenceId());
    return;
  }
  // Carry out any memory based logic
  // Commit the load within the LSQ
  if (insn->isLoad()) loadStoreQueue_.commitLoad(insn);
  // Add the store address uop to the completedStoreAddrUops_ queue to keep an
  // in program-order list of store address uops
  if (insn->isStoreAddress()) completedStoreAddrUops_.push(insn);
  // Commit the store address uop within the LSQ associated with the passed
  // store data uop
  if (insn->isStoreData()) {
    assert((completedStoreAddrUops_.front()->getInstructionId() ==
                insn->getInstructionId() &&
            completedStoreAddrUops_.front()->getMicroOpIndex() ==
                insn->getMicroOpIndex()) &&
           "[SimEng:Core] Attempted to complete a store macro-op out of "
           "program order");
    loadStoreQueue_.commitStore(completedStoreAddrUops_.front());
    completedStoreAddrUops_.pop();
  }

  staging_.recordRetired(insn->getSequenceId());
}

void Core::applyStateChange(const OS::ProcessStateChange& change) {
  // Update registers in accoradance with the ProcessStateChange type
  switch (change.type) {
    case OS::ChangeType::INCREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() +
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    case OS::ChangeType::DECREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(
            change.modifiedRegisters[i],
            registerFileSet_.get(change.modifiedRegisters[i]).get<uint64_t>() -
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    default: {  // OS::ChangeType::REPLACEMENT
      // If type is ChangeType::REPLACEMENT, set new values
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        registerFileSet_.set(change.modifiedRegisters[i],
                             change.modifiedRegisterValues[i]);
      }
      break;
    }
  }

  // Update memory
  // TODO: Analyse if ChangeType::INCREMENT or ChangeType::DECREMENT case is
  // required for memory changes
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    mmu_->requestWrite(change.memoryAddresses[i], change.memoryAddressValues[i],
                       0);
  }
}

void Core::schedule(simeng::OS::cpuContext newContext) {
  currentTID_ = newContext.TID;
  fetchUnit_.setProgramLength(newContext.progByteLen);
  fetchUnit_.updatePC(newContext.pc);
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      registerFileSet_.set({(uint8_t)type, (uint16_t)tag},
                           newContext.regFile[type][tag]);
    }
  }
  status_ = CoreStatus::executing;
  procTicks_ = 0;
  isa_.updateAfterContextSwitch(newContext);
  mmu_->setTid(currentTID_);
  // Allow fetch unit to resume fetching instructions & incrementing PC
  fetchUnit_.unpause();
}

bool Core::interrupt() {
  if (exceptionGenerated_ == false) {
    status_ = CoreStatus::switching;
    contextSwitches_++;
    // Stop fetch unit from incrementing PC or fetching next instructions
    // (also flushes loop buffer and any pending completed reads).
    fetchUnit_.pause();
    return true;
  }
  return false;
}

uint64_t Core::getCurrentProcTicks() const { return procTicks_; }

simeng::OS::cpuContext Core::getCurrentContext() const {
  OS::cpuContext newContext;
  newContext.TID = currentTID_;
  newContext.pc =
      exceptionGenerated_
          ? exceptionGeneratingInstruction_->getInstructionAddress() + 4
          : fetchUnit_.getPC();
  // progByteLen will not change in process so do not need to set it
  // Don't need to explicitly save SP as will be in reg file contents
  auto regFileStruc = isa_.getRegisterFileStructures();
  newContext.regFile.resize(regFileStruc.size());
  for (size_t i = 0; i < regFileStruc.size(); i++) {
    newContext.regFile[i].resize(regFileStruc[i].quantity);
  }
  // Set all reg Values
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      newContext.regFile[type][tag] =
          registerFileSet_.get({(uint8_t)type, (uint16_t)tag});
    }
  }
  // Do not need to explicitly set newContext.sp as it will be included in
  // regFile
  return newContext;
}

}  // namespace inorder
}  // namespace models
}  // namespace simeng
