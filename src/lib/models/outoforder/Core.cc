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
           uint64_t processMemorySize, uint64_t entryPoint,
           const arch::Architecture& isa, BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator, YAML::Node config,
           Statistics& stats)
    : isa_(isa),
      stats_(stats),
      physicalRegisterStructures_(
          {{8, config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>()},
           {256,
            config["Register-Set"]["FloatingPoint/SVE-Count"].as<uint16_t>()},
           {32, config["Register-Set"]["Predicate-Count"].as<uint16_t>()},
           {1, config["Register-Set"]["Conditional-Count"].as<uint16_t>()},
           {8, isa.getNumSystemRegisters()}}),
      physicalRegisterQuantities_(
          {config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>(),
           config["Register-Set"]["FloatingPoint/SVE-Count"].as<uint16_t>(),
           config["Register-Set"]["Predicate-Count"].as<uint16_t>(),
           config["Register-Set"]["Conditional-Count"].as<uint16_t>(),
           isa.getNumSystemRegisters()}),
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
          stats_, config["LSQ-L1-Interface"]["Exclusive"].as<bool>(),
          config["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
              .as<uint16_t>()),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, config["Fetch"]["Fetch-Block-Size"].as<uint16_t>(),
                 isa, branchPredictor, stats_),
      reorderBuffer_(
          config["Queue-Sizes"]["ROB"].as<unsigned int>(), registerAliasTable_,
          loadStoreQueue_,
          [this](auto instruction) { raiseException(instruction); },
          [this](auto branchAddress) {
            fetchUnit_.registerLoopBoundary(branchAddress);
          },
          branchPredictor, config["Fetch"]["Loop-Buffer-Size"].as<uint16_t>(),
          config["Fetch"]["Loop-Detection-Threshold"].as<uint16_t>(), stats_),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor,
                  stats_),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures_.size(), stats_),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_, config,
                         stats_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto insnId) { reorderBuffer_.commitMicroOps(insnId); },
          stats_),
      portAllocator_(portAllocator),
      clockFrequency_(config["Core"]["Clock-Frequency"].as<float>() * 1e9),
      commitWidth_(config["Pipeline-Widths"]["Commit"].as<unsigned int>()),
      config_(config) {
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
        [](auto uop) { uop->setCommitReady(); }, branchPredictor, stats_,
        config["Execution-Units"][i]["Pipelined"].as<bool>(), blockingGroups);
  }
  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);

  // Register stat counters
  ticksCntr_ = stats_.registerStat("core.cycles");
  flushesCntr_ = stats_.registerStat("core.flushes");

  for (int i = 0;
       i <
       std::min(commitWidth_, config["Queue-Sizes"]["ROB"].as<unsigned int>()) +
           1;
       i++) {
    std::ostringstream statName;
    statName << "rob.commits." << i;
    commitCntrs_.push_back(stats_.registerStat(statName.str()));
  }
};

void Core::tick() {
  stats_.incrementStat(ticksCntr_, 1);

  if (hasHalted_) return;

  if (hasHalted_) return;

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
  unsigned int commitQuantity = reorderBuffer_.commit(commitWidth_);
#if SIMENG_ENABLE_VERBOSE_STATS
  stats_.incrementStat(commitCntrs_[commitQuantity], 1);
#endif

  if (exceptionGenerated_) {
    handleException();
    fetchUnit_.requestFromPC();
    return;
  }

  flushIfNeeded();
  fetchUnit_.requestFromPC();
  isa_.updateSystemTimerRegisters(&registerFileSet_,
                                  stats_.getFullSimStat(ticksCntr_));
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

    stats_.incrementStat(flushesCntr_, 1);
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.flushLoopBuffer();
    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    stats_.incrementStat(flushesCntr_, 1);
  }
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
  return stats_.getFullSimStat(ticksCntr_) / (clockFrequency_ / 1e9);
}

std::map<std::string, std::string> Core::getStats() const {
  std::map<std::string, std::string> finalStatDump = {
      {"branch.executed", "0"},     {"branch.mispredict", "0"},
      {"core.cycles", "0"},         {"core.flushes", "0"},
      {"issue.backendStalls", "0"}, {"issue.frontendStalls", "0"},
      {"rob.retired", "0"}};
  stats_.fillSimulationStats(finalStatDump);

#if SIMENG_ENABLE_VERBOSE_STATS
  stats_.dumpFullStats();
#endif

  // Calculate IPC
  auto ipc = std::stoi(finalStatDump["rob.retired"]) /
             static_cast<float>(stats_.getFullSimStat(ticksCntr_));
  std::ostringstream ipcStr;
  ipcStr << std::setprecision(2) << ipc;
  finalStatDump["ipc"] = ipcStr.str();

  // Calculate the branch miss rate
  auto branchMissRate =
      100.0f *
      static_cast<float>(std::stoi(finalStatDump["branch.mispredict"])) /
      static_cast<float>(std::stoi(finalStatDump["branch.executed"]));
  std::ostringstream branchMissRateStr;
  branchMissRateStr << std::setprecision(3) << branchMissRate << "%";
  finalStatDump["branch.missrate"] = branchMissRateStr.str();

  return finalStatDump;
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
