#include "simeng/models/outoforder/Core.hh"

#include <algorithm>
#include <cstdint>
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
Core::Core(const arch::Architecture& isa, BranchPredictor& branchPredictor,
           std::shared_ptr<memory::MMU> mmu,
           pipeline::PortAllocator& portAllocator,
           arch::sendSyscallToHandler handleSyscall,
           std::function<void(OS::cpuContext, uint16_t, CoreStatus, uint64_t)>
               updateCoreDescInOS,
           ryml::ConstNodeRef config)
    : isa_(isa),
      physicalRegisterStructures_(isa.getConfigPhysicalRegisterStructure()),
      physicalRegisterQuantities_(isa.getConfigPhysicalRegisterQuantities()),
      registerFileSet_(physicalRegisterStructures_),
      registerAliasTable_(config::SimInfo::getArchRegStruct(),
                          physicalRegisterQuantities_),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
      mmu_(mmu),
      fetchToDecodeBuffer_(
          config::SimInfo::getValue<int>(config["Pipeline-Widths"]["FrontEnd"]),
          {}),
      decodeToRenameBuffer_(
          config::SimInfo::getValue<int>(config["Pipeline-Widths"]["FrontEnd"]),
          nullptr),
      renameToDispatchBuffer_(
          config::SimInfo::getValue<int>(config["Pipeline-Widths"]["FrontEnd"]),
          nullptr),
      issuePorts_(config["Execution-Units"].num_children(), {1, nullptr}),
      completionSlots_(config["Execution-Units"].num_children() +
                           config::SimInfo::getValue<int>(
                               config["Pipeline-Widths"]["LSQ-Completion"]),
                       {1, nullptr}),
      loadStoreQueue_(
          config::SimInfo::getValue<uint32_t>(config["Queue-Sizes"]["Load"]),
          config::SimInfo::getValue<uint32_t>(config["Queue-Sizes"]["Store"]),
          mmu_,
          {completionSlots_.data() + config["Execution-Units"].num_children(),
           config::SimInfo::getValue<size_t>(
               config["Pipeline-Widths"]["LSQ-Completion"])},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          simeng::pipeline::CompletionOrder::OUTOFORDER),
      fetchUnit_(fetchToDecodeBuffer_, mmu_,
                 config::SimInfo::getValue<uint16_t>(
                     config["Fetch"]["Fetch-Block-Size"]),
                 isa, branchPredictor),
      reorderBuffer_(
          config::SimInfo::getValue<uint32_t>(config["Queue-Sizes"]["ROB"]),
          registerAliasTable_, loadStoreQueue_,
          [this](auto instruction) { raiseException(instruction); },
          [this](auto branchAddress) {
            fetchUnit_.registerLoopBoundary(branchAddress);
          },
          branchPredictor,
          config::SimInfo::getValue<uint16_t>(
              config["Fetch"]["Loop-Buffer-Size"]),
          config::SimInfo::getValue<uint16_t>(
              config["Fetch"]["Loop-Detection-Threshold"])),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures_.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto reg) { dispatchIssueUnit_.setRegisterReady(reg); },
          [](auto seqId) { return true; },
          [this](auto insn) { microOpWriteback(insn); }),
      portAllocator_(portAllocator),
      commitWidth_(
          config::SimInfo::getValue<int>(config["Pipeline-Widths"]["Commit"])),
      handleSyscall_(handleSyscall),
      updateCoreDescInOS_(updateCoreDescInOS) {
  for (size_t i = 0; i < config["Execution-Units"].num_children(); i++) {
    // Create vector of blocking groups
    std::vector<uint16_t> blockingGroups = {};
    for (ryml::ConstNodeRef grp :
         config["Execution-Units"][i]["Blocking-Group-Nums"]) {
      blockingGroups.push_back(config::SimInfo::getValue<uint16_t>(grp));
    }
    executionUnits_.emplace_back(
        issuePorts_[i], completionSlots_[i],
        [this](auto regs, auto values) {
          dispatchIssueUnit_.forwardOperands(regs, values);
        },
        [this](auto uop) { loadStoreQueue_.startLoad(uop); },
        [this](auto uop) { loadStoreQueue_.supplyStoreData(uop); },
        [](auto uop) { uop->setCommitReady(); }, branchPredictor,
        config::SimInfo::getValue<bool>(
            config["Execution-Units"][i]["Pipelined"]),
        blockingGroups);
  }
  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });
  // Create exception handler based on chosen architecture
  exceptionHandlerFactory(config::SimInfo::getISA());
}

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
          renameToDispatchBuffer_.isEmpty() && !mmu_->hasPendingRequests() &&
          (reorderBuffer_.size() == 0) && (exceptionGenerated_ == false)) {
        // Flush pipeline
        fetchUnit_.flushLoopBuffer();
        decodeUnit_.purgeFlushed();
        dispatchIssueUnit_.purgeFlushed();
        dispatchIssueUnit_.flush();
        writebackUnit_.flush();
        status_ = CoreStatus::idle;
        // Update status of corresponding CoreDesc in SimOS as there is no
        // causal action originating from SimOS which caused this change in
        // Core.
        updateCoreDescInOS_(getCurrentContext(true), getCoreId(),
                            CoreStatus::idle, 0);
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

  if (exceptionGenerated_) {
    exception_ticks_++;
    processException();
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
  // reorderBuffer_.commit(commitWidth_);
  if (reorderBuffer_.commit(commitWidth_, ticks_) == 0)
    noactivity_++;
  else
    noactivity_ = 0;

  if (noactivity_ != 0 && (noactivity_ == 1000000)) {
    // status_ = CoreStatus::halted;
    // Update status of corresponding CoreDesc in SimOS as there is no
    // causal action originating from SimOS which caused this change in
    // Core.
    // updateCoreDescInOS_(getCurrentContext(), getCoreId(), CoreStatus::halted,
    //                     0);
    // currentTID_ = -1;
    std::cout << "[SimEng:Core" << coreId_ << ":TID" << currentTID_
              << "] no activity for " << noactivity_
              << " cycles total, last committed address was 0x" << std::hex
              << reorderBuffer_.getLastAddr() << std::dec << " and 0x"
              << std::hex << reorderBuffer_.getHeadOfBuffer() << std::dec
              << " at the HEAD of the ROB" << std::endl;
  }

  if (exceptionGenerated_) {
    handleException();
    return;
  }

  flushIfNeeded();
}

void Core::flushIfNeeded() {
  // Check for flush
  bool euFlush = false;
  uint64_t targetAddress = 0;
  uint64_t lowestInsnId = 0;
  for (const auto& eu : executionUnits_) {
    if (eu.shouldFlush() && (!euFlush || eu.getFlushInsnId() < lowestInsnId)) {
      euFlush = true;
      lowestInsnId = eu.getFlushInsnId();
      targetAddress = eu.getFlushAddress();
    }
  }
  if (euFlush || reorderBuffer_.shouldFlush()) {
    // Flush was requested in an out-of-order stage.
    // Update PC and wipe in-order buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch)

    if (reorderBuffer_.shouldFlush() &&
        (!euFlush || reorderBuffer_.getFlushInsnId() < lowestInsnId)) {
      // If the reorder buffer found an older instruction to flush up to, do
      // that instead
      lowestInsnId = reorderBuffer_.getFlushInsnId();
      targetAddress = reorderBuffer_.getFlushAddress();
    }
    // if (currentTID_ == 24)
    //   std::cerr << "### FLUSHING AT 0x" << std::hex << lowestInsnId <<
    //   std::dec
    //             << std::endl;

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    decodeToRenameBuffer_.fill(nullptr);
    decodeToRenameBuffer_.stall(false);

    renameToDispatchBuffer_.fill(nullptr);
    renameToDispatchBuffer_.stall(false);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer_.flush(lowestInsnId);
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

CoreStatus Core::getStatus() { return status_; }

void Core::setStatus(CoreStatus newStatus) { status_ = newStatus; }

uint64_t Core::getCurrentTID() const { return currentTID_; }

uint16_t Core::getCoreId() const { return coreId_; }

void Core::setCoreId(uint16_t id) { coreId_ = id; }

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
  fetchUnit_.flushLoopBuffer();
  decodeUnit_.purgeFlushed();
  dispatchIssueUnit_.purgeFlushed();
  loadStoreQueue_.purgeFlushed();
  for (auto& eu : executionUnits_) {
    eu.purgeFlushed();
  }

  exceptionHandler_->registerException(exceptionGeneratingInstruction_);
  processException();
}

void Core::processException() {
  assert(exceptionGenerated_ != false &&
         "[SimEng:Core] Attempted to process an exception handler that wasn't "
         "active");
  if (mmu_->hasPendingRequests()) {
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
  // if (getArchitecturalRegisterFileSet().get({0, 8}).get<uint64_t>() != 98) {
  //   outputFile_ << "\tSyscall "
  //               << getArchitecturalRegisterFileSet().get({0,
  //               8}).get<uint64_t>()
  //               << " results" << std::endl;
  //   outputFile_ << "\tfatal: " << result.fatal << std::endl;
  //   outputFile_ << "\tidleAftersycall: " << result.idleAfterSyscall
  //               << std::endl;
  // }

  if (result.fatal) {
    status_ = CoreStatus::halted;
    // Update status of corresponding CoreDesc in SimOS as there is no
    // causal action originating from SimOS which caused this change in
    // Core.
    updateCoreDescInOS_(getCurrentContext(), getCoreId(), CoreStatus::halted,
                        0);
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
    if (result.idleAfterSyscall) {
      // Update status of corresponding CoreDesc in SimOS as there is no
      // causal action originating from SimOS which caused this change in
      // Core.
      // Enusre all pipeline stages are flushed
      dispatchIssueUnit_.flush();
      writebackUnit_.flush();
      // Update core status
      status_ = CoreStatus::idle;
      contextSwitches_++;
      updateCoreDescInOS_(getCurrentContext(true), getCoreId(),
                          CoreStatus::idle, 0);
    }
  }

  exceptionGenerated_ = false;
}

void Core::applyStateChange(const OS::ProcessStateChange& change) {
  // Update registers in accoradance with the ProcessStateChange type
  switch (change.type) {
    case OS::ChangeType::INCREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        mappedRegisterFileSet_.set(
            change.modifiedRegisters[i],
            mappedRegisterFileSet_.get(change.modifiedRegisters[i])
                    .get<uint64_t>() +
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    case OS::ChangeType::DECREMENT: {
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        mappedRegisterFileSet_.set(
            change.modifiedRegisters[i],
            mappedRegisterFileSet_.get(change.modifiedRegisters[i])
                    .get<uint64_t>() -
                change.modifiedRegisterValues[i].get<uint64_t>());
      }
      break;
    }
    default: {  // OS::ChangeType::REPLACEMENT
      // If type is ChangeType::REPLACEMENT, set new values
      for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
        // outputFile_ << "\t{" << unsigned(change.modifiedRegisters[i].type)
        //             << ":" << change.modifiedRegisters[i].tag << "}"
        //             << " <- " << std::hex;
        // for (int j = change.modifiedRegisterValues[i].size() - 1; j >= 0;
        // j--) {
        //   if (change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j] <
        //   16)
        //     outputFile_ << "0";
        //   outputFile_ << unsigned(
        //       change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j]);
        // }
        // outputFile_ << std::dec << std::endl;
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
    // outputFile_ << "\tAddr " << std::hex << change.memoryAddresses[i].vaddr
    //             << std::dec << " <- " << std::hex;
    // for (int j = change.memoryAddressValues[i].size() - 1; j >= 0; j--) {
    //   if (change.memoryAddressValues[i].getAsVector<uint8_t>()[j] < 16)
    //     outputFile_ << "0";
    //   outputFile_ << unsigned(
    //       change.memoryAddressValues[i].getAsVector<uint8_t>()[j]);
    // }
    // outputFile_ << std::dec << std::endl;
    mmu_->requestWrite(change.memoryAddresses[i],
                       change.memoryAddressValues[i]);
  }
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return mappedRegisterFileSet_;
}

void Core::microOpWriteback(const std::shared_ptr<Instruction>& insn) {
  // If the passed instruction is a micro-op, communicate to the ROB that it
  // is ready to commit
  if (insn->isMicroOp()) {
    insn->setWaitingCommit();
    reorderBuffer_.commitMicroOps(insn->getInstructionId());
  } else {
    insn->setCommitReady();
  }
}

void Core::sendSyscall(OS::SyscallInfo syscallInfo) const {
  handleSyscall_(syscallInfo);
}

void Core::receiveSyscallResult(const OS::SyscallResult result) const {
  exceptionHandler_->processSyscallResult(result);
}

uint64_t Core::getInstructionsRetiredCount() const {
  return reorderBuffer_.getInstructionsCommittedCount();
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = reorderBuffer_.getInstructionsCommittedCount();
  auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  auto fetchStalls = fetchUnit_.getFetchStalls();

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

  std::map<std::string, std::string> stats = {
      {"cycles", std::to_string(ticks_)},
      {"retired", std::to_string(retired)},
      {"ipc", ipcStr.str()},
      {"flushes", std::to_string(flushes_)},
      {"fetch.fetchStalls", std::to_string(fetchStalls)},
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
      {"exception.ticks", std::to_string(exception_ticks_)},
      {"context.switches", std::to_string(contextSwitches_)},
      {"rob.numLoadsRetired", std::to_string(reorderBuffer_.getNumLoads())},
      {"rob.numStoresRetired", std::to_string(reorderBuffer_.getNumStores())}};

  const std::vector<uint64_t> possibleIssues =
      dispatchIssueUnit_.getPossibleIssues();
  const std::vector<uint64_t> actualIssues =
      dispatchIssueUnit_.getActualIssues();
  for (int i = 0; i < possibleIssues.size(); i++) {
    std::ostringstream key;
    key << "issue.Port" << i << ".balance";
    std::ostringstream val;
    val << std::to_string(actualIssues[i]) << "/"
        << std::to_string(possibleIssues[i]) << "(" << std::setprecision(3)
        << (float(actualIssues[i]) / float(possibleIssues[i])) * 100 << "%)";
    stats[key.str()] = val.str();
  }

  // std::map<uint64_t, uint64_t> lsqLatencies =
  // loadStoreQueue_.getLatencies(); std::map<uint64_t, uint64_t>::iterator
  // it;
  // for (it = lsqLatencies.begin(); it != lsqLatencies.end(); it++) {
  //   if (it->second > 10) {
  //     std::ostringstream key;
  //     key << "lsq.latency_" << it->first;
  //     std::ostringstream val;
  //     val << it->second;
  //     stats[key.str()] = val.str();
  //   }
  // }

  return stats;
}

void Core::schedule(simeng::OS::cpuContext newContext) {
  // Need to reset mapping in register file
  registerAliasTable_.reset(config::SimInfo::getArchRegStruct(),
                            physicalRegisterQuantities_);

  currentTID_ = newContext.TID;

  // outputFile_.close();
  // std::ostringstream str;
  // str << "/Users/jj16791/workspace/simeng" << currentTID_ << "Retire.out";
  // outputFile_.open(str.str(), std::ofstream::out | std::ofstream::app);

  reorderBuffer_.setTid(currentTID_);
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
  mmu_->setTid(currentTID_);
  loadStoreQueue_.setTid(currentTID_);
  // Allow fetch unit to resume fetching instructions & incrementing PC
  fetchUnit_.unpause();
}

bool Core::interrupt() {
  if (exceptionGenerated_ == false) {
    status_ = CoreStatus::switching;
    contextSwitches_++;
    // Stop fetch unit from incrementing PC or fetching next instructions
    fetchUnit_.pause();
    return true;
  }
  return false;
}

uint64_t Core::getCurrentProcTicks() const { return procTicks_; }

simeng::OS::cpuContext Core::getCurrentContext(bool clearTID) {
  OS::cpuContext newContext;
  newContext.TID = currentTID_;
  newContext.pc =
      exceptionGenerated_
          ? exceptionGeneratingInstruction_->getInstructionAddress() + 4
          : fetchUnit_.getPC();
  // progByteLen will not change in process so do not need to set it
  // Don't need to explicitly save SP as will be in reg file contents
  auto regFileStruc = config::SimInfo::getArchRegStruct();
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
  if (clearTID) currentTID_ = -1;
  // Do not need to explicitly set newContext.sp as it will be included in
  // regFile
  return newContext;
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
