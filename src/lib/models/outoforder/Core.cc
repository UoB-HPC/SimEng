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

bool print = false;

// TODO: System register count has to match number of supported system registers
Core::Core(arch::Architecture& isa, BranchPredictor& branchPredictor,
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
          [this](auto insn) { microOpWriteback(insn); },
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          }),
      portAllocator_(portAllocator),
      commitWidth_(
          config::SimInfo::getValue<int>(config["Pipeline-Widths"]["Commit"])),
      branchPredictor_(branchPredictor),
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
        [](auto uop) { uop->setCommitReady(); },
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

  numCommitted_.resize(commitWidth_ + 1);
}

void Core::tick() {
  ticks_++;
  subTicks_++;
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
        loadStoreQueue_.drainSTB();
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
  unsigned int numRet = reorderBuffer_.commit(commitWidth_);
  if (numRet == 16) {
    getStats();
    // dispatchIssueUnit_.resetStats();
  }
  if (numRet == 17) getStats();
  if (numRet <= commitWidth_) numCommitted_[numRet]++;
  // if (reorderBuffer_.commit(commitWidth_, ticks_) == 0)
  //   noactivity_++;
  // else
  //   noactivity_ = 0;

  // if (noactivity_ != 0 && (noactivity_ == 1000000)) {
  //   // status_ = CoreStatus::halted;
  //   // Update status of corresponding CoreDesc in SimOS as there is no
  //   // causal action originating from SimOS which caused this change in
  //   // Core.
  //   // updateCoreDescInOS_(getCurrentContext(), getCoreId(),
  //   CoreStatus::halted,
  //   //                     0);
  //   // currentTID_ = -1;
  //   std::cout << "[SimEng:Core" << coreId_ << ":TID" << currentTID_
  //             << "] no activity for " << noactivity_
  //             << " cycles total, last committed address was 0x" << std::hex
  //             << reorderBuffer_.getLastAddr() << std::dec << " and 0x"
  //             << std::hex << reorderBuffer_.getHeadOfBuffer() << std::dec
  //             << " at the HEAD of the ROB" << std::endl;
  // }

  if (subTicks_ > 10000000) {
    uint64_t committed = reorderBuffer_.getInstructionsCommittedCount();
    std::cout << "[SimEng:Core" << coreId_ << ":TID" << currentTID_
              << "] Instructions retired so far: "
              << FormatWithCommas<uint64_t>(committed) << " (+"
              << (committed - subInsns_) << " instructions)" << std::endl;
    subTicks_ = 0;
    subInsns_ = committed;
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
    fetchToDecodeBuffer_.flushBranchMacroOps(branchPredictor_);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    decodeToRenameBuffer_.flushBranchMicroOps(branchPredictor_);
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
    fetchToDecodeBuffer_.flushBranchMacroOps(branchPredictor_);
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
  // Check for branch instructions in buffer, and flush them from the BP.
  // Then empty the buffers
  fetchToDecodeBuffer_.flushBranchMacroOps(branchPredictor_);
  fetchToDecodeBuffer_.fill({});
  fetchToDecodeBuffer_.stall(false);

  decodeToRenameBuffer_.flushBranchMicroOps(branchPredictor_);
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
  loadStoreQueue_.drainSTB();
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
  if (print) {
    outputFile_ << "\tSyscall "
                << getArchitecturalRegisterFileSet().get({0, 8}).get<uint64_t>()
                << " results" << std::endl;
    outputFile_ << "\tfatal: " << result.fatal << std::endl;
    outputFile_ << "\tidleAftersycall: " << result.idleAfterSyscall
                << std::endl;
    outputFile2_
        << "\tSyscall "
        << getArchitecturalRegisterFileSet().get({0, 8}).get<uint64_t>()
        << " results" << std::endl;
    outputFile2_ << "\tfatal: " << result.fatal << std::endl;
    outputFile2_ << "\tidleAftersycall: " << result.idleAfterSyscall
                 << std::endl;
  }

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
      // std::cerr << coreId_ << "/" << currentTID_ << ": IDLE after "
      //           << getArchitecturalRegisterFileSet().get({0,
      //           8}).get<uint64_t>()
      //           << " syscall" << std::endl;
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
        if (print) {
          outputFile_ << "\t{" << unsigned(change.modifiedRegisters[i].type)
                      << ":" << change.modifiedRegisters[i].tag << "}"
                      << " <- " << std::hex;
          outputFile2_ << "\t{" << unsigned(change.modifiedRegisters[i].type)
                       << ":" << change.modifiedRegisters[i].tag << "}"
                       << " <- " << std::hex;
          for (int j = change.modifiedRegisterValues[i].size() - 1; j >= 0;
               j--) {
            if (change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j] <
                16) {
              outputFile_ << "0";
              outputFile2_ << "0";
            }
            outputFile_ << unsigned(
                change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j]);
            outputFile2_ << unsigned(
                change.modifiedRegisterValues[i].getAsVector<uint8_t>()[j]);
          }
          outputFile_ << std::dec << std::endl;
          outputFile2_ << std::dec << std::endl;
        }
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
    if (print) {
      outputFile_ << "\tAddr " << std::hex << change.memoryAddresses[i].vaddr
                  << std::dec << " <- " << std::hex;
      outputFile2_ << "\tAddr " << std::hex << change.memoryAddresses[i].vaddr
                   << std::dec << " <- " << std::hex;
      for (int j = change.memoryAddressValues[i].size() - 1; j >= 0; j--) {
        if (change.memoryAddressValues[i].getAsVector<uint8_t>()[j] < 16) {
          outputFile_ << "0";
          outputFile2_ << "0";
        }
        outputFile_ << unsigned(
            change.memoryAddressValues[i].getAsVector<uint8_t>()[j]);
        outputFile2_ << unsigned(
            change.memoryAddressValues[i].getAsVector<uint8_t>()[j]);
      }
      outputFile_ << std::dec << std::endl;
      outputFile2_ << std::dec << std::endl;
    }
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

  uint64_t totalBranchesFetched = fetchUnit_.getBranchFetchedCount();
  uint64_t totalBranchesRetired = reorderBuffer_.getRetiredBranchesCount();
  uint64_t totalBranchMispredicts = reorderBuffer_.getBranchMispredictedCount();

  auto branchMissRate = 100.0f * static_cast<float>(totalBranchMispredicts) /
                        static_cast<float>(totalBranchesRetired);
  std::ostringstream branchMissRateStr;
  branchMissRateStr << std::setprecision(3) << branchMissRate << "%";

  std::map<std::string, std::string> stats = {
      {"cycles", FormatWithCommas<uint64_t>(ticks_)},
      {"retired", FormatWithCommas<uint64_t>(retired)},
      {"ipc", ipcStr.str()},
      {"flushes", FormatWithCommas<uint64_t>(flushes_)},
      {"fetch.fetchStalls", FormatWithCommas<uint64_t>(fetchStalls)},
      {"decode.earlyFlushes", FormatWithCommas<uint64_t>(earlyFlushes)},
      {"rename.allocationStalls", FormatWithCommas<uint64_t>(allocationStalls)},
      {"rename.robStalls", FormatWithCommas<uint64_t>(robStalls)},
      {"rename.lqStalls", FormatWithCommas<uint64_t>(lqStalls)},
      {"rename.sqStalls", FormatWithCommas<uint64_t>(sqStalls)},
      {"dispatch.rsStalls", FormatWithCommas<uint64_t>(rsStalls)},
      {"issue.frontendStalls", FormatWithCommas<uint64_t>(frontendStalls)},
      {"issue.backendStalls", FormatWithCommas<uint64_t>(backendStalls)},
      {"issue.portBusyStalls", FormatWithCommas<uint64_t>(portBusyStalls)},
      {"branch.fetch", FormatWithCommas<uint64_t>(totalBranchesFetched)},
      {"branch.retired", FormatWithCommas<uint64_t>(totalBranchesRetired)},
      {"branch.mispredict", FormatWithCommas<uint64_t>(totalBranchMispredicts)},
      {"branch.missrate", branchMissRateStr.str()},
      {"lsq.loadViolations",
       FormatWithCommas<uint64_t>(reorderBuffer_.getViolatingLoadsCount())},
      {"idle.ticks", FormatWithCommas<uint64_t>(idle_ticks_)},
      {"exception.ticks", FormatWithCommas<uint64_t>(exception_ticks_)},
      {"context.switches", FormatWithCommas<uint64_t>(contextSwitches_)},
      {"rob.numLoadsRetired",
       FormatWithCommas<uint64_t>(reorderBuffer_.getNumLoads())},
      {"rob.numStoresRetired",
       FormatWithCommas<uint64_t>(reorderBuffer_.getNumStores())},
      {"lsq.STBSupplies",
       FormatWithCommas<uint64_t>(loadStoreQueue_.getSTBSupplies())},
      {"lsq.STBDrains",
       FormatWithCommas<uint64_t>(loadStoreQueue_.getSTBDrains())},
      {"lsq.conflicts",
       FormatWithCommas<uint64_t>(loadStoreQueue_.getConflicts())},
      {"lsq.loadRequests",
       FormatWithCommas<uint64_t>(loadStoreQueue_.getNumLoadReqs())},
      {"lsq.storeRequests",
       FormatWithCommas<uint64_t>(loadStoreQueue_.getNumStoreReqs())}};

  const std::vector<uint64_t> possibleIssues =
      dispatchIssueUnit_.getPossibleIssues();
  const std::vector<uint64_t> actualIssues =
      dispatchIssueUnit_.getActualIssues();
  for (int i = 0; i < possibleIssues.size(); i++) {
    std::ostringstream key;
    key << "issue.Port" << i << ".balance";
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(actualIssues[i]) << "/"
        << FormatWithCommas<uint64_t>(possibleIssues[i]) << "("
        << std::setprecision(3)
        << (float(actualIssues[i]) / float(possibleIssues[i])) * 100 << "%)";
    stats[key.str()] = val.str();
  }

  const std::vector<uint64_t> rsStallsPort =
      dispatchIssueUnit_.getRSStallsPort();
  for (int i = 0; i < rsStallsPort.size(); i++) {
    std::ostringstream key;
    key << "dispatch.RS" << i << ".rsStall";
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(rsStallsPort[i]);
    stats[key.str()] = val.str();
  }

  const std::vector<uint64_t> frontendStallsPort =
      dispatchIssueUnit_.getFrontendStallsPort();
  for (int i = 0; i < frontendStallsPort.size(); i++) {
    std::ostringstream key;
    key << "issue.Port" << i << ".frontendStall";
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(frontendStallsPort[i]);
    stats[key.str()] = val.str();
  }

  const std::vector<uint64_t> backendStallsPort =
      dispatchIssueUnit_.getBackendStallsPort();
  for (int i = 0; i < backendStallsPort.size(); i++) {
    std::ostringstream key;
    key << "issue.Port" << i << ".backendStall";
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(backendStallsPort[i]);
    stats[key.str()] = val.str();
  }

  const std::map<uint64_t, uint64_t> waitingOn = reorderBuffer_.getWaitingOn();
  for (const auto& wait : waitingOn) {
    std::ostringstream key;
    key << "rob.waitingOn." << wait.first;
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(wait.second);
    stats[key.str()] = val.str();
  }

  for (int i = 0; i < numCommitted_.size(); i++) {
    std::ostringstream key;
    key << "rob.commit." << i;
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(numCommitted_[i]);
    stats[key.str()] = val.str();
  }

  for (int i = 0; i < executionUnits_.size(); i++) {
    std::ostringstream key;
    key << "eu." << i << ".cycles";
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(executionUnits_[i].getCycles());
    stats[key.str()] = val.str();
  }

  std::map<uint64_t, uint64_t> latMap = loadStoreQueue_.getLatMap();

  // Get top 10
  std::vector<uint64_t> top10 = {};
  for (auto const& x : latMap) {
    if (top10.size()) {
      if (top10.size() < 10 || x.second > top10.back()) {
        auto it = top10.begin();
        for (; it < top10.end(); it++) {
          if (x.second > latMap.at(*it)) {
            top10.insert(it, x.first);
            break;
          }
        }
      }
      if (top10.size() > 10) top10.pop_back();
    } else
      top10.push_back(x.first);
  }
  for (auto& x : top10) {
    std::ostringstream key;
    key << "lsq.latency." << x;
    std::ostringstream val;
    val << FormatWithCommas<uint64_t>(latMap.at(x));
    stats[key.str()] = val.str();
  }

  // std::map<uint64_t, uint64_t> lsqLatencies = loadStoreQueue_.getLatencies();
  // std::map<uint64_t, uint64_t>::iterator it;
  // for (it = lsqLatencies.begin(); it != lsqLatencies.end(); it++) {
  //   if (it->second > 10) {
  //     std::ostringstream key;
  //     key << "lsq.latency_" << it->first;
  //     std::ostringstream val;
  //     val << it->second;
  //     stats[key.str()] = val.str();
  //   }
  // }

  for (const auto& [key, value] : stats) {
    std::cout << "[SimEng] " << key << ": " << value << std::endl;
  }
  return stats;
}

void Core::schedule(simeng::OS::cpuContext newContext) {
  // Need to reset mapping in register file
  registerAliasTable_.reset(config::SimInfo::getArchRegStruct(),
                            physicalRegisterQuantities_);

  currentTID_ = newContext.TID;

  outputFile_.close();
  std::ostringstream str;
  str << "/Users/jj16791/workspace/simengRetire.out";
  outputFile_.open(str.str(), std::ofstream::out | std::ofstream::app);

  outputFile2_.close();
  std::ostringstream str2;
  str2 << "/Users/jj16791/workspace/simengRetireWithIDs.out";
  outputFile2_.open(str2.str(), std::ofstream::out | std::ofstream::app);

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
