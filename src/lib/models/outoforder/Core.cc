#include "simeng/models/outoforder/Core.hh"

#include <algorithm>
#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

namespace simeng {
namespace models {
namespace outoforder {

Core::Core(memory::MemoryInterface& instructionMemory,
           memory::MemoryInterface& dataMemory, uint64_t processMemorySize,
           uint64_t entryPoint, const arch::Architecture& isa,
           BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator, ryml::ConstNodeRef config)
    : simeng::Core(dataMemory, isa, config::SimInfo::getPhysRegStruct()),
      physicalRegisterStructures_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterQuantities_(config::SimInfo::getPhysRegQuantities()),
      registerAliasTable_(config::SimInfo::getArchRegStruct(),
                          physicalRegisterQuantities_),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
      fetchToDecodeBuffer_(config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(),
                           {}),
      decodeToRenameBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(), nullptr),
      renameToDispatchBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(), nullptr),
      issuePorts_(config["Execution-Units"].num_children(), {1, nullptr}),
      completionSlots_(
          config["Execution-Units"].num_children() +
              config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>(),
          {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, config["Fetch"]["Fetch-Block-Size"].as<uint16_t>(),
                 isa, branchPredictor,
                 config::SimInfo::getConfig()["Fetch"]["MOP-Queue-Size"]
                     .as<uint16_t>(),
                 config::SimInfo::getConfig()["Fetch"]["MOP-Cache-Tag-Bits"]
                     .as<uint16_t>()),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures_.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto insnId) { reorderBuffer_.commitMicroOps(insnId); }),
      reorderBuffer_(
          config["Queue-Sizes"]["ROB"].as<uint32_t>(), registerAliasTable_,
          loadStoreQueue_,
          [this](auto instruction) { raiseException(instruction); },
          branchPredictor),
      loadStoreQueue_(
          config["Queue-Sizes"]["Load"].as<uint32_t>(),
          config["Queue-Sizes"]["Store"].as<uint32_t>(), dataMemory,
          {completionSlots_.data() + config["Execution-Units"].num_children(),
           config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>()},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          [](auto uop) { uop->setCommitReady(); },
          config["LSQ-L1-Interface"]["Exclusive"].as<bool>(),
          config["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
              .as<uint16_t>()),
      portAllocator_(portAllocator),
      commitWidth_(config["Pipeline-Widths"]["Commit"].as<uint16_t>()) {
  for (size_t i = 0; i < config["Execution-Units"].num_children(); i++) {
    // Create vector of blocking groups
    std::vector<uint16_t> blockingGroups = {};
    for (ryml::ConstNodeRef grp :
         config["Execution-Units"][i]["Blocking-Group-Nums"]) {
      blockingGroups.push_back(grp.as<uint16_t>());
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
  portAllocator.setRSSizeGetter([this](std::vector<uint32_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
}

void Core::tick() {
  if (hasHalted_) return;

  ticks_++;
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);

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
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
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
    return;
  }

  flushIfNeeded();
  isa_.updateSystemTimerRegisters(&registerFileSet_, ticks_);
}

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, there
  // are no uops at the head of any buffer, and no exception is currently being
  // handled.
  if (!fetchUnit_.hasHalted()) {
    return false;
  }

  if (reorderBuffer_.size() > 0) {
    return false;
  }

  auto decodeSlots = fetchToDecodeBuffer_.getHeadSlots();
  for (size_t slot = 0; slot < fetchToDecodeBuffer_.getWidth(); slot++) {
    if (decodeSlots[slot].size() > 0) {
      return false;
    }
  }

  auto renameSlots = decodeToRenameBuffer_.getHeadSlots();
  for (size_t slot = 0; slot < decodeToRenameBuffer_.getWidth(); slot++) {
    if (renameSlots[slot] != nullptr) {
      return false;
    }
  }

  if (exceptionHandler_ != nullptr) return false;

  return true;
}

const ArchitecturalRegisterFileSet& Core::getArchitecturalRegisterFileSet()
    const {
  return mappedRegisterFileSet_;
}

uint64_t Core::getInstructionsRetiredCount() const {
  return reorderBuffer_.getInstructionsCommittedCount();
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = reorderBuffer_.getInstructionsCommittedCount();
  auto ipc = retired / static_cast<float>(ticks_);

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

  std::map<std::string, std::string> stats_ = {
      {"cycles", formatWithCommas<uint64_t>(ticks_)},
      {"retired", formatWithCommas<uint64_t>(retired)},
      {"ipc", formatWithCommas<float>(ipc)},
      {"flushes", formatWithCommas<uint64_t>(flushes_)},
      {"fetch.branchStalls", formatWithCommas<uint64_t>(branchStalls)},
      {"decode.earlyFlushes", formatWithCommas<uint64_t>(earlyFlushes)},
      {"rename.allocationStalls", formatWithCommas<uint64_t>(allocationStalls)},
      {"rename.robStalls", formatWithCommas<uint64_t>(robStalls)},
      {"rename.lqStalls", formatWithCommas<uint64_t>(lqStalls)},
      {"rename.sqStalls", formatWithCommas<uint64_t>(sqStalls)},
      {"dispatch.rsStalls", formatWithCommas<uint64_t>(rsStalls)},
      {"issue.frontendStalls", formatWithCommas<uint64_t>(frontendStalls)},
      {"issue.backendStalls", formatWithCommas<uint64_t>(backendStalls)},
      {"issue.portBusyStalls", formatWithCommas<uint64_t>(portBusyStalls)},
      {"branch.executed", formatWithCommas<uint64_t>(totalBranchesExecuted)},
      {"branch.mispredict", formatWithCommas<uint64_t>(totalBranchMispredicts)},
      {"branch.missrate", formatWithCommas<float>(branchMissRate) + "%"},
      {"lsq.loadViolations",
       formatWithCommas<uint64_t>(reorderBuffer_.getViolatingLoadsCount())}};

  // // Get port index to name mappings
  // ryml::ConstNodeRef config = config::SimInfo::getConfig();
  // std::map<uint16_t, std::string> portIdxToNames;
  // for (uint16_t i = 0; i < config["Ports"].num_children(); i++) {
  //   portIdxToNames[i] = config["Ports"][i]["Portname"].as<std::string>();
  // }

  // std::vector<uint64_t> feSlotStalls =
  //     dispatchIssueUnit_.getFrontendSlotStalls();
  // uint64_t feTotalSlotStalls = 0;
  // std::vector<uint64_t> beSlotStalls =
  //     dispatchIssueUnit_.getBackendSlotStalls();
  // uint64_t beTotalSlotStalls = 0;

  // for (int i = 0; i < feSlotStalls.size(); i++) {
  //   stats_["issue.frontendSlotStall." + portIdxToNames[i]] =
  //       formatWithCommas<uint64_t>(feSlotStalls[i]);
  //   feTotalSlotStalls += feSlotStalls[i];
  //   stats_["issue.backendSlotStall." + portIdxToNames[i]] =
  //       formatWithCommas<uint64_t>(beSlotStalls[i]);
  //   beTotalSlotStalls += beSlotStalls[i];
  // }
  // stats_["issue.frontendTotalSlotStalls"] =
  //     formatWithCommas<uint64_t>(feTotalSlotStalls);
  // stats_["issue.backendTotalSlotStalls"] =
  //     formatWithCommas<uint64_t>(beTotalSlotStalls);

  // std::map<uint64_t, std::vector<uint64_t>> issueGroupUsage =
  //     dispatchIssueUnit_.getIssueGroupUsage();
  // for (const auto& keyVal : issueGroupUsage) {
  //   std::string key = "issue.portUsage.";
  //   for (int i = 0; i < 64; i++) {
  //     if (keyVal.first & (1ull << i)) {
  //       if (key != "issue.portUsage.") key += "|";
  //       key += portIdxToNames[i];
  //     }
  //   }
  //   for (int i = 0; i < keyVal.second.size(); i++) {
  //     if (keyVal.second[i])
  //       stats_[key + "." + portIdxToNames[i]] =
  //           formatWithCommas<uint64_t>(keyVal.second[i]);
  //   }
  // }

  // for (int i = 0; i < fetchToDecodeBuffer_.getWidth(); i++) {
  //   std::pair<uint64_t, uint64_t> usagePair =
  //       fetchToDecodeBuffer_.getUsage()[i];
  //   stats_["fetchToDecodeBuffer_.usage." + std::to_string(i)] =
  //       formatWithCommas<uint64_t>(usagePair.first) + "/" +
  //       formatWithCommas<uint64_t>(usagePair.second);
  // }
  // for (int i = 0; i < decodeToRenameBuffer_.getWidth(); i++) {
  //   std::pair<uint64_t, uint64_t> usagePair =
  //       decodeToRenameBuffer_.getUsage()[i];
  //   stats_["decodeToRenameBuffer_.usage." + std::to_string(i)] =
  //       formatWithCommas<uint64_t>(usagePair.first) + "/" +
  //       formatWithCommas<uint64_t>(usagePair.second);
  // }
  // for (int i = 0; i < renameToDispatchBuffer_.getWidth(); i++) {
  //   std::pair<uint64_t, uint64_t> usagePair =
  //       renameToDispatchBuffer_.getUsage()[i];
  //   stats_["renameToDispatchBuffer_.usage." + std::to_string(i)] =
  //       formatWithCommas<uint64_t>(usagePair.first) + "/" +
  //       formatWithCommas<uint64_t>(usagePair.second);
  // }
  // for (int j = 0; j < issuePorts_.size(); j++) {
  //   for (int i = 0; i < issuePorts_[j].getWidth(); i++) {
  //     std::pair<uint64_t, uint64_t> usagePair = issuePorts_[j].getUsage()[i];
  //     stats_["issuePorts_." + portIdxToNames[j] + ".usage"] =
  //         formatWithCommas<uint64_t>(usagePair.first) + "/" +
  //         formatWithCommas<uint64_t>(usagePair.second);
  //   }
  // }
  // for (int j = 0; j < completionSlots_.size(); j++) {
  //   for (int i = 0; i < completionSlots_[j].getWidth(); i++) {
  //     std::pair<uint64_t, uint64_t> usagePair =
  //         completionSlots_[j].getUsage()[i];
  //     stats_["completionSlots_." + std::to_string(j) + ".usage"] =
  //         formatWithCommas<uint64_t>(usagePair.first) + "/" +
  //         formatWithCommas<uint64_t>(usagePair.second);
  //   }
  // }

  // std::vector<std::vector<uint64_t>> emptyAtIssueNoDeps =
  //     dispatchIssueUnit_.getEmptyAtIssueNoDeps();
  // for (int i = 0; i < emptyAtIssueNoDeps.size(); i++) {
  //   for (int j = 0; j < emptyAtIssueNoDeps[i].size(); j++) {
  //     if (emptyAtIssueNoDeps[i][j] > 0) {
  //       stats_["issue.emptyButAvailable." + portIdxToNames[i] + "." +
  //              portIdxToNames[j]] =
  //           formatWithCommas<uint64_t>(emptyAtIssueNoDeps[i][j]);
  //     }
  //   }
  // }

  // std::vector<std::vector<uint64_t>> emptyAtIssueWithDeps =
  //     dispatchIssueUnit_.getEmptyAtIssueWithDeps();
  // for (int i = 0; i < emptyAtIssueWithDeps.size(); i++) {
  //   for (int j = 0; j < emptyAtIssueWithDeps[i].size(); j++) {
  //     if (emptyAtIssueWithDeps[i][j] > 0) {
  //       stats_["issue.onlyDepsButAvailable." + portIdxToNames[i] + "." +
  //              portIdxToNames[j]] =
  //           formatWithCommas<uint64_t>(emptyAtIssueWithDeps[i][j]);
  //     }
  //   }
  // }

  // std::vector<std::vector<uint64_t>> rsMiss = dispatchIssueUnit_.getRsMiss();
  // for (int i = 0; i < rsMiss.size(); i++) {
  //   for (int j = 0; j < rsMiss[i].size(); j++) {
  //     if (rsMiss[i][j] > 0) {
  //       stats_["dispatch.rsMiss." + portIdxToNames[i] + "." +
  //              std::to_string(j)] = formatWithCommas<uint64_t>(rsMiss[i][j]);
  //     }
  //   }
  // }

  return stats_;
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
  // This must happen prior to handling the exception to ensure the commit state
  // is up-to-date with the register mapping table
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
    hasHalted_ = true;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
  }

  exceptionHandler_ = nullptr;
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

    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    flushes_++;
  }
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
