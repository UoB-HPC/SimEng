#include "simeng/models/outoforder/Core.hh"

#include <iomanip>
#include <sstream>
#include <string>

namespace simeng {
namespace models {
namespace outoforder {

Core::Core(memory::MemoryInterface& instructionMemory,
           memory::MemoryInterface& dataMemory,
           const uint64_t processMemorySize, const uint64_t entryPoint,
           const arch::Architecture& isa, BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator,
           const ryml::ConstNodeRef config,
           const bool offloadingEnabled)
    : simeng::Core(dataMemory, isa, config::SimInfo::getPhysRegStruct()),
      offloadingEnabled_(offloadingEnabled),
      physicalRegisterStructures_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterQuantities_(config::SimInfo::getPhysRegQuantities()),
      registerAliasTable_(config::SimInfo::getArchRegStruct(),
                          physicalRegisterQuantities_),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
      fetchToDecodeBuffer_(config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(),
                           {}),
      decodeToRenameBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(), nullptr),
      offloadingToRenameBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(), nullptr),
      renameToDispatchBuffer_(
          config["Pipeline-Widths"]["FrontEnd"].as<uint16_t>(), nullptr),
      issuePorts_(config["Execution-Units"].num_children(), {1, nullptr}),
      completionSlots_(
          config["Execution-Units"].num_children() +
              config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>() +
              1,  // One slot for offloading controller
          {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, config["Fetch"]["Fetch-Block-Size"].as<uint16_t>(),
                 isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(offloadingEnabled_ ? offloadingToRenameBuffer_
                                     : decodeToRenameBuffer_,
                  renameToDispatchBuffer_, reorderBuffer_, registerAliasTable_,
                  loadStoreQueue_, physicalRegisterStructures_.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto insnId) { reorderBuffer_.commitMicroOps(insnId); }),
      reorderBuffer_(
          config["Queue-Sizes"]["ROB"].as<uint32_t>(), registerAliasTable_,
          loadStoreQueue_,
          [this](const auto& instruction) { raiseException(instruction); },
          [this](auto branchAddress) {
            fetchUnit_.registerLoopBoundary(branchAddress);
          },
          branchPredictor, config["Fetch"]["Loop-Buffer-Size"].as<uint16_t>(),
          config["Fetch"]["Loop-Detection-Threshold"].as<uint16_t>()),
      loadStoreQueue_(
          config["Queue-Sizes"]["Load"].as<uint32_t>(),
          config["Queue-Sizes"]["Store"].as<uint32_t>(), dataMemory,
          {completionSlots_.data() + config["Execution-Units"].num_children(),
           config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>()},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          [](const auto& uop) { uop->setCommitReady(); },
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
      offloadingController_(
          decodeToRenameBuffer_, offloadingToRenameBuffer_,
          completionSlots_[completionSlots_.size() - 1],
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          [](const auto& uop) { uop->setCommitReady(); }),
      commitWidth_(config["Pipeline-Widths"]["Commit"].as<uint16_t>()),
      branchPredictor_(branchPredictor) {
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
        [this](const auto& uop) { loadStoreQueue_.startLoad(uop); },
        [this](const auto& uop) { loadStoreQueue_.supplyStoreData(uop); },
        [](const auto& uop) { uop->setCommitReady(); },
        config["Execution-Units"][i]["Pipelined"].as<bool>(), blockingGroups);
  }
  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint32_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });

  // Query and apply initial state
  const auto state = isa.getInitialState();
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
  if (offloadingEnabled_) {
    offloadingController_.tick();
  }
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
  if (offloadingEnabled_) {
    offloadingToRenameBuffer_.tick();
  }
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

  const auto decodeSlots = fetchToDecodeBuffer_.getHeadSlots();
  for (size_t slot = 0; slot < fetchToDecodeBuffer_.getWidth(); slot++) {
    if (!decodeSlots[slot].empty()) {
      return false;
    }
  }

  const auto renameSlots = decodeToRenameBuffer_.getHeadSlots();
  for (size_t slot = 0; slot < decodeToRenameBuffer_.getWidth(); slot++) {
    if (renameSlots[slot] != nullptr) {
      return false;
    }
  }

  if (offloadingEnabled_) {
    const auto offloadingSlots = offloadingToRenameBuffer_.getHeadSlots();
    for (size_t slot = 0; slot < offloadingToRenameBuffer_.getWidth(); slot++) {
      if (offloadingSlots[slot] != nullptr) {
        return false;
      }
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
  const auto retired = reorderBuffer_.getInstructionsCommittedCount();
  const auto ipc = retired / static_cast<float>(ticks_);
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;

  const auto branchStalls = fetchUnit_.getBranchStalls();

  const auto earlyFlushes = decodeUnit_.getEarlyFlushes();

  const auto allocationStalls = renameUnit_.getAllocationStalls();
  const auto robStalls = renameUnit_.getROBStalls();
  const auto lqStalls = renameUnit_.getLoadQueueStalls();
  const auto sqStalls = renameUnit_.getStoreQueueStalls();

  const auto rsStalls = dispatchIssueUnit_.getRSStalls();
  const auto frontendStalls = dispatchIssueUnit_.getFrontendStalls();
  const auto backendStalls = dispatchIssueUnit_.getBackendStalls();
  const auto portBusyStalls = dispatchIssueUnit_.getPortBusyStalls();

  const uint64_t totalBranchesFetched = fetchUnit_.getBranchFetchedCount();
  const uint64_t totalBranchesRetired =
      reorderBuffer_.getRetiredBranchesCount();
  const uint64_t totalBranchMispredicts =
      reorderBuffer_.getBranchMispredictedCount();

  const auto branchMissRate = 100.0 *
                              static_cast<double>(totalBranchMispredicts) /
                              static_cast<double>(totalBranchesRetired);
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
          {"branch.fetched", std::to_string(totalBranchesFetched)},
          {"branch.retired", std::to_string(totalBranchesRetired)},
          {"branch.mispredicted", std::to_string(totalBranchMispredicts)},
          {"branch.missrate", branchMissRateStr.str()},
          {"lsq.loadViolations",
           std::to_string(reorderBuffer_.getViolatingLoadsCount())}};
}

void Core::raiseException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  // Check for branch instructions in buffer, and flush them from the BP.
  // Then empty the buffers
  branchPredictor_.flushBranchesInBufferFromSelf(fetchToDecodeBuffer_);
  fetchToDecodeBuffer_.fill({});
  fetchToDecodeBuffer_.stall(false);

  branchPredictor_.flushBranchesInBufferFromSelf(decodeToRenameBuffer_);
  decodeToRenameBuffer_.fill(nullptr);
  decodeToRenameBuffer_.stall(false);

  if (offloadingEnabled_) {
    offloadingToRenameBuffer_.fill(nullptr);
    offloadingToRenameBuffer_.stall(false);
  }

  // Instructions in this buffer are already accounted for in the ROB so no
  // need to check for branch instructions in this buffer
  renameToDispatchBuffer_.fill(nullptr);
  renameToDispatchBuffer_.stall(false);

  // Flush everything younger than the exception-generating instruction.
  // This must happen prior to handling the exception to ensure the commit state
  // is up-to-date with the register mapping table
  reorderBuffer_.flush(exceptionGeneratingInstruction_->getInstructionId());
  decodeUnit_.purgeFlushed();
  if (offloadingEnabled_) {
    offloadingController_.purgeFlushed();
  }
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

  const bool success = exceptionHandler_->tick();
  if (!success) {
    // Exception handler requires further ticks to complete
    return;
  }

  const auto& [fatal, instructionAddress, stateChange] =
      exceptionHandler_->getResult();

  if (fatal) {
    hasHalted_ = true;
    std::cout << "[SimEng:Core] Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(instructionAddress);
    applyStateChange(stateChange);
  }

  exceptionHandler_ = nullptr;
}

void Core::flushIfNeeded() {
  // Check for flush

  // pair<targetAddress, lowestInsnId>
  std::optional<std::pair<uint64_t, uint64_t>> flush{};
  for (const auto& eu : executionUnits_) {
    if (eu.shouldFlush()) {
      if (!flush.has_value() || eu.getFlushInsnId() < flush.value().second) {
        flush = {eu.getFlushAddress(), eu.getFlushInsnId()};
      }
    }
  }
  if (flush.has_value() || reorderBuffer_.shouldFlush() ||
      offloadingController_.shouldFlush()) {
    // Flush was requested in an out-of-order stage.
    // Update PC and wipe in-order buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch)

    if (reorderBuffer_.shouldFlush()) {
      if (!flush.has_value() ||
          reorderBuffer_.getFlushInsnId() < flush.value().second) {
        flush = {reorderBuffer_.getFlushAddress(),
                 reorderBuffer_.getFlushInsnId()};
      }
    }
    if (offloadingController_.shouldFlush()) {
      const auto& cause = offloadingController_.getFlushInsn();
      const auto flushId = cause->getInstructionId();
      if (!flush.has_value() || flushId < flush.value().second) {
        const auto flushAddr =
            reorderBuffer_.findInstructionAfter(cause)->getInstructionAddress();
        flush = {flushAddr, flushId};
      }
    }
    assert(flush.has_value());
    const auto [targetAddress, lowestInsnId] = flush.value();

    // Check for branch instructions in buffer, and flush them from the BP.
    // Then empty the buffers
    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    branchPredictor_.flushBranchesInBufferFromSelf(fetchToDecodeBuffer_);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    branchPredictor_.flushBranchesInBufferFromSelf(decodeToRenameBuffer_);
    decodeToRenameBuffer_.fill(nullptr);
    decodeToRenameBuffer_.stall(false);

    if (offloadingEnabled_) {
      branchPredictor_.flushBranchesInBufferFromSelf(offloadingToRenameBuffer_);
      offloadingToRenameBuffer_.fill(nullptr);
      offloadingToRenameBuffer_.stall(false);
    }

    // Instructions in this buffer are already accounted for in the ROB so no
    // need to check for branch instructions in this buffer
    renameToDispatchBuffer_.fill(nullptr);
    renameToDispatchBuffer_.stall(false);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer_.flush(lowestInsnId);
    decodeUnit_.purgeFlushed();
    if (offloadingEnabled_) {
      offloadingController_.purgeFlushed();
    }
    dispatchIssueUnit_.purgeFlushed();
    loadStoreQueue_.purgeFlushed();
    for (auto& eu : executionUnits_) {
      eu.purgeFlushed();
    }

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    const auto targetAddress = decodeUnit_.getFlushAddress();

    // Check for branch instructions in buffer, and flush them from the BP.
    // Then empty the buffers
    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    branchPredictor_.flushBranchesInBufferFromSelf(fetchToDecodeBuffer_);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    flushes_++;
  }
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
