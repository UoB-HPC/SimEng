#include "simeng/models/outoforder/Core.hh"

#include <algorithm>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

// Temporary; until config options are available
#include "simeng/arch/aarch64/Instruction.hh"
namespace simeng {
namespace models {
namespace outoforder {

// TODO: System register count has to match number of supported system registers
Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           const arch::Architecture& isa, BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator, YAML::Node& config)
    : isa_(isa),
      physicalRegisterStructures_(isa.getConfigPhysicalRegisterStructure()),
      physicalRegisterQuantities_(isa.getConfigPhysicalRegisterQuantities()),
      registerFileSet_(physicalRegisterStructures_),
      registerAliasTable_(isa.getRegisterFileStructures(),
                          physicalRegisterQuantities_),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
      dataMemory_(dataMemory),
      fetchToDecodeBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<unsigned int>(), {}),
      decodeToRenameBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<unsigned int>(), nullptr),
      renameToDispatchBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<unsigned int>(), nullptr),
      issuePorts_(config["Execution-Units"].size(), {1, nullptr}),
      completionSlots_(
          config["Execution-Units"].size() +
              config["Pipeline-Widths"]["LSQ-Completion"].as<unsigned int>(),
          {1, nullptr}),
      loadStoreQueue_(
          config["Queue-Sizes"]["Load"].as<unsigned int>(),
          config["Queue-Sizes"]["Store"].as<unsigned int>(), dataMemory,
          {completionSlots_.data() + config["Execution-Units"].size(),
           config["Pipeline-Widths"]["LSQ-Completion"].as<unsigned int>()},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          config["LSQ-L1-Interface"]["Exclusive"].as<bool>(),
          config["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
              .as<uint16_t>()),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory,
                 config["Fetch"]["Fetch-Block-Size"].as<uint16_t>(), isa,
                 branchPredictor),
      reorderBuffer_(
          config["Queue-Sizes"]["ROB"].as<unsigned int>(), registerAliasTable_,
          loadStoreQueue_,
          [this](auto instruction) { raiseException(instruction); },
          [this](auto branchAddress) {
            fetchUnit_.registerLoopBoundary(branchAddress);
          },
          branchPredictor, config["Fetch"]["Loop-Buffer-Size"].as<uint16_t>(),
          config["Fetch"]["Loop-Detection-Threshold"].as<uint16_t>()),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures_.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto insnId) { reorderBuffer_.commitMicroOps(insnId); }),
      portAllocator_(portAllocator),
      clockFrequency_(config["Core"]["Clock-Frequency"].as<float>() * 1e9),
      commitWidth_(config["Pipeline-Widths"]["Commit"].as<unsigned int>()) {
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
          dispatchIssueUnit_.forwardOperands(regs, values);
        },
        [this](auto uop) { loadStoreQueue_.startLoad(uop); },
        [this](auto uop) { loadStoreQueue_.supplyStoreData(uop); },
        [](auto uop) { uop->setCommitReady(); }, branchPredictor,
        config["Execution-Units"][i]["Pipelined"].as<bool>(), blockingGroups);
  }
  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });
};

void Core::tick() {
  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

  switch (status_) {
    case CoreStatus::idle:
      idle_ticks_++;
      return;
    case CoreStatus::switching: {
      // Ensure that all pipeline buffers and ROB are empty, no data requests
      // are pending, and no exception is being handled before context switching
      if (fetchToDecodeBuffer_.isEmpty() && decodeToRenameBuffer_.isEmpty() &&
          renameToDispatchBuffer_.isEmpty() &&
          !dataMemory_.hasPendingRequests() && (reorderBuffer_.size() == 0) &&
          (exceptionHandler_ == nullptr)) {
        // Flush pipeline
        fetchUnit_.flushLoopBuffer();
        decodeUnit_.purgeFlushed();
        dispatchIssueUnit_.purgeFlushed();
        dispatchIssueUnit_.flush();
        writebackUnit_.flush();
        status_ = CoreStatus::idle;
        return;
      }
      break;
    }
    case CoreStatus::halted:
      return;
    case CoreStatus::executing:
      break;
  }

  // Increase tick count for current process execution
  procTicks_++;

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

  // Tick port allocators internal functionality at start of cycle
  portAllocator_.tick();

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();

  // Tick units
  fetchUnit_.tick();
  decodeUnit_.tick();
  renameUnit_.tick();
  dispatchIssueUnit_.tick();
  for (auto& eu : executionUnits_) {
    // Tick each execution unit
    eu.tick();
  }

  loadStoreQueue_.tick();

  // Late tick for the dispatch/issue unit to issue newly ready uops
  dispatchIssueUnit_.issue();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after
  // use, as these will now loop around and become the tail.
  fetchToDecodeBuffer_.tick();
  decodeToRenameBuffer_.tick();
  renameToDispatchBuffer_.tick();
  for (auto& issuePort : issuePorts_) {
    issuePort.tick();
  }
  for (auto& completionSlot : completionSlots_) {
    completionSlot.tick();
  }

  // Commit instructions from ROB
  reorderBuffer_.commit(commitWidth_);

  if (exceptionGenerated_) {
    handleException();
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
  if (euFlush || reorderBuffer_.shouldFlush()) {
    // Flush was requested in an out-of-order stage.
    // Update PC and wipe in-order buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch)

    if (reorderBuffer_.shouldFlush() &&
        (!euFlush || reorderBuffer_.getFlushSeqId() < lowestSeqId)) {
      // If the reorder buffer found an older instruction to flush up to, do
      // that instead
      lowestSeqId = reorderBuffer_.getFlushSeqId();
      targetAddress = reorderBuffer_.getFlushAddress();
    }

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    decodeToRenameBuffer_.fill(nullptr);
    decodeToRenameBuffer_.stall(false);

    renameToDispatchBuffer_.fill(nullptr);
    renameToDispatchBuffer_.stall(false);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer_.flush(lowestSeqId);
    decodeUnit_.purgeFlushed();
    dispatchIssueUnit_.purgeFlushed();
    loadStoreQueue_.purgeFlushed();
    for (auto& eu : executionUnits_) {
      eu.purgeFlushed();
    }

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    flushes_++;
  }
}

CoreStatus Core::getStatus() {
  // Core is considered to have halted when the fetch unit has halted, there
  // are no uops at the head of any buffer, and no exception is currently
  // being handled.
  if (fetchUnit_.hasHalted() && !(reorderBuffer_.size() > 0) &&
      (exceptionHandler_ == nullptr)) {
    bool decodeSlotEmpty = true;
    auto decodeSlots = fetchToDecodeBuffer_.getHeadSlots();
    for (size_t slot = 0; slot < fetchToDecodeBuffer_.getWidth(); slot++) {
      if (decodeSlots[slot].size() > 0) {
        decodeSlotEmpty = false;
        break;
      }
    }
    if (decodeSlotEmpty) {
      bool renameSlotEmpty = true;
      auto renameSlots = decodeToRenameBuffer_.getHeadSlots();
      for (size_t slot = 0; slot < decodeToRenameBuffer_.getWidth(); slot++) {
        if (renameSlots[slot] != nullptr) {
          renameSlotEmpty = false;
          break;
        }
      }
      if (renameSlotEmpty) {
        status_ = CoreStatus::halted;
      }
    }
  }

  return status_;
}

void Core::raiseException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  fetchToDecodeBuffer_.fill({});
  fetchToDecodeBuffer_.stall(false);

  decodeToRenameBuffer_.fill(nullptr);
  decodeToRenameBuffer_.stall(false);

  renameToDispatchBuffer_.fill(nullptr);
  renameToDispatchBuffer_.stall(false);

  // Flush everything younger than the exception-generating instruction.
  // This must happen prior to handling the exception to ensure the commit
  // state is up-to-date with the register mapping table
  reorderBuffer_.flush(exceptionGeneratingInstruction_->getInstructionId());
  decodeUnit_.purgeFlushed();
  dispatchIssueUnit_.purgeFlushed();
  loadStoreQueue_.purgeFlushed();
  for (auto& eu : executionUnits_) {
    eu.purgeFlushed();
  }

  exceptionGenerated_ = false;
  exceptionHandler_ =
      isa_.handleException(exceptionGeneratingInstruction_, *this, dataMemory_);
  processExceptionHandler();
}

void Core::processExceptionHandler() {
  assert(exceptionHandler_ != nullptr &&
         "Attempted to process an exception handler that wasn't present");
  if (dataMemory_.hasPendingRequests()) {
    // Must wait for all memory requests to complete before processing the
    // exception
    return;
  }

  bool success = exceptionHandler_->tick();
  if (!success) {
    // Exception handler requires further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    status_ = CoreStatus::halted;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
  }

  exceptionHandler_ = nullptr;
}

void Core::applyStateChange(const arch::ProcessStateChange& change) {
  // Update registers in accoradance with the ProcessStateChange type
  switch (change.type) {
    case arch::ChangeType::INCREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        mappedRegisterFileSet_.set(
            change.modifiedRegisters[i],
            mappedRegisterFileSet_.get(change.modifiedRegisters[i])
                    .get<uint64_t>() +
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    case arch::ChangeType::DECREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        mappedRegisterFileSet_.set(
            change.modifiedRegisters[i],
            mappedRegisterFileSet_.get(change.modifiedRegisters[i])
                    .get<uint64_t>() -
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    default: {  // arch::ChangeType::REPLACEMENT
      // If type is ChangeType::REPLACEMENT, set new values
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        mappedRegisterFileSet_.set(change.modifiedRegisters[i],
                                   change.modifiedRegisterValues[i]);
      }
      break;
    }
  }

  // Update memory
  // TODO: Analyse if ChangeType::INCREMENT or ChangeType::DECREMENT case is
  // required for memory changes
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    dataMemory_.requestWrite(change.memoryAddresses[i],
                             change.memoryAddressValues[i]);
  }
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return mappedRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return reorderBuffer_.getInstructionsCommittedCount();
}

uint64_t Core::getSystemTimer() const {
  // TODO: This will need to be changed if we start supporting DVFS.
  return ticks_ / (clockFrequency_ / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = reorderBuffer_.getInstructionsCommittedCount();
  auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  auto branchStalls = fetchUnit_.getBranchStalls();

  auto earlyFlushes = decodeUnit_.getEarlyFlushes();

  auto allocationStalls = renameUnit_.getAllocationStalls();
  auto robStalls = renameUnit_.getROBStalls();
  auto lqStalls = renameUnit_.getLoadQueueStalls();
  auto sqStalls = renameUnit_.getStoreQueueStalls();

  auto rsStalls = dispatchIssueUnit_.getRSStalls();
  auto frontendStalls = dispatchIssueUnit_.getFrontendStalls();
  auto backendStalls = dispatchIssueUnit_.getBackendStalls();
  auto portBusyStalls = dispatchIssueUnit_.getPortBusyStalls();

  uint64_t totalBranchesExecuted = 0;
  uint64_t totalBranchMispredicts = 0;

  // Sum up the branch stats reported across the execution units.
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
          {"rename.allocationStalls", std::to_string(allocationStalls)},
          {"rename.robStalls", std::to_string(robStalls)},
          {"rename.lqStalls", std::to_string(lqStalls)},
          {"rename.sqStalls", std::to_string(sqStalls)},
          {"dispatch.rsStalls", std::to_string(rsStalls)},
          {"issue.frontendStalls", std::to_string(frontendStalls)},
          {"issue.backendStalls", std::to_string(backendStalls)},
          {"issue.portBusyStalls", std::to_string(portBusyStalls)},
          {"branch.executed", std::to_string(totalBranchesExecuted)},
          {"branch.mispredict", std::to_string(totalBranchMispredicts)},
          {"branch.missrate", branchMissRateStr.str()},
          {"lsq.loadViolations",
           std::to_string(reorderBuffer_.getViolatingLoadsCount())},
          {"idle.ticks", std::to_string(idle_ticks_)},
          {"context.switches", std::to_string(contextSwitches_)}};
}

void Core::schedule(simeng::OS::cpuContext newContext) {
  // Need to reset mapping in register file
  registerAliasTable_.reset(isa_.getRegisterFileStructures(),
                            physicalRegisterQuantities_);

  currentTID_ = newContext.TID;
  fetchUnit_.setProgramLength(newContext.progByteLen);
  fetchUnit_.updatePC(newContext.pc);
  for (size_t type = 0; type < newContext.regFile.size(); type++) {
    for (size_t tag = 0; tag < newContext.regFile[type].size(); tag++) {
      mappedRegisterFileSet_.set({(uint8_t)type, (uint16_t)tag},
                                 newContext.regFile[type][tag]);
    }
  }
  status_ = CoreStatus::executing;
  procTicks_ = 0;
  isa_.updateAfterContextSwitch(newContext);
  // Allow fetch unit to resume fetching instructions & incrementing PC
  fetchUnit_.unpause();
}

bool Core::interrupt() {
  if (exceptionHandler_ == nullptr) {
    status_ = CoreStatus::switching;
    contextSwitches_++;
    // Stop fetch unit from incrementing PC or fetching next instructions
    fetchUnit_.pause();
    return true;
  }
  return false;
}

uint64_t Core::getCurrentProcTicks() const { return procTicks_; }

simeng::OS::cpuContext Core::getCurrentContext() const {
  OS::cpuContext newContext;
  newContext.TID = currentTID_;
  newContext.pc = fetchUnit_.getPC();
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
          mappedRegisterFileSet_.get({(uint8_t)type, (uint16_t)tag});
    }
  }
  // Do not need to explicitly set newContext.sp as it will be included in
  // regFile
  return newContext;
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
