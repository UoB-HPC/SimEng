#include "simeng/models/outoforder/Core.hh"

#include <algorithm>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sstream>
#include <string>

// Temporary; until config options are available
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace models {
namespace outoforder {

// TODO: Replace with config options
// TODO: Physical registers are configured for TX2 booted with 4-way SMT
// TODO: System register count has to match number of supported system registers
const std::initializer_list<uint16_t> physicalRegisterQuantities = {96, 128,
                                                                    48, 128, 7};
const std::initializer_list<RegisterFileStructure> physicalRegisterStructures =
    {{8, 96}, {256, 128}, {32, 48}, {1, 128}, {8, 7}};
const unsigned int robSize = 128;
const unsigned int loadQueueSize = 160;
const unsigned int storeQueueSize = 192;
const unsigned int fetchBlockAlignmentBits = 5;
const unsigned int frontendWidth = 4;
const unsigned int commitWidth = 4;
const unsigned int executionUnitCount = 8;
const unsigned int lsqCompletionSlots = 2;
const unsigned int clockFrequency = 2.5 * 1e9;
const uint8_t dispatchRate = 2;
const uint64_t L1Bandwidth = 64;
const uint8_t permittedLoadsPerCycle = 2;

Core::Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
           uint64_t processMemorySize, uint64_t entryPoint,
           const arch::Architecture& isa, BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator, 
           std::vector<std::pair<uint8_t, uint64_t>> rsArrangement)
    : isa_(isa),
      registerFileSet_(physicalRegisterStructures),
      registerAliasTable_(isa.getRegisterFileStructures(),
                          physicalRegisterQuantities),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
      dataMemory_(dataMemory),
      fetchToDecodeBuffer_(frontendWidth, {}),
      decodeToRenameBuffer_(frontendWidth, nullptr),
      renameToDispatchBuffer_(frontendWidth, nullptr),
      issuePorts_(executionUnitCount, {1, nullptr}),
      completionSlots_(executionUnitCount + lsqCompletionSlots, {1, nullptr}),
      loadStoreQueue_(
          loadQueueSize, storeQueueSize, dataMemory,
          {completionSlots_.data() + executionUnitCount, lsqCompletionSlots},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          }, L1Bandwidth, permittedLoadsPerCycle),
      reorderBuffer_(robSize, registerAliasTable_, loadStoreQueue_,
                     [this](auto instruction) { raiseException(instruction); }),
      fetchUnit_(fetchToDecodeBuffer_, instructionMemory, processMemorySize,
                 entryPoint, fetchBlockAlignmentBits, isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities, rsArrangement,
                         dispatchRate),
      writebackUnit_(completionSlots_, registerFileSet_) {
  for (size_t i = 0; i < executionUnitCount; i++) {
    executionUnits_.emplace_back(
        issuePorts_[i], completionSlots_[i],
        [this](auto regs, auto values) {
          dispatchIssueUnit_.forwardOperands(regs, values);
        },
        [this](auto uop) { loadStoreQueue_.startLoad(uop); }, [](auto uop) {},
        [](auto uop) { uop->setCommitReady(); }, branchPredictor);
  }
  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {dispatchIssueUnit_.getRSSizes(sizeVec);});

  // Query and apply initial state
  auto state = isa.getInitialState();
  applyStateChange(state);
};

void Core::tick() {
  ticks_++;

  if (exceptionHandler_ != nullptr) {
    processExceptionHandler();
    return;
  }

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
  reorderBuffer_.commit(commitWidth);

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

    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});
    fetchToDecodeBuffer_.stall(false);

    decodeToRenameBuffer_.fill(nullptr);
    decodeToRenameBuffer_.stall(false);

    renameToDispatchBuffer_.fill(nullptr);
    renameToDispatchBuffer_.stall(false);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer_.flush(lowestSeqId);
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

bool Core::hasHalted() const {
  if (hasHalted_) {
    return true;
  }

  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
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

  return true;
}

void Core::raiseException(std::shared_ptr<Instruction>& instruction) {
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
  reorderBuffer_.flush(exceptionGeneratingInstruction_->getSequenceId());
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

  bool success = exceptionHandler_->tick();
  if (!success) {
    // Exception handler requires further ticks to complete
    return;
  }

  const auto& result = exceptionHandler_->getResult();

  if (result.fatal) {
    hasHalted_ = true;
    std::cout << "Halting due to fatal exception" << std::endl;
  } else {
    fetchUnit_.updatePC(result.instructionAddress);
    applyStateChange(result.stateChange);
  }

  exceptionHandler_ = nullptr;
}

void Core::applyStateChange(const arch::ProcessStateChange& change) {
  // Update registers
  for (size_t i = 0; i < change.modifiedRegisters.size(); i++) {
    mappedRegisterFileSet_.set(change.modifiedRegisters[i],
                               change.modifiedRegisterValues[i]);
  }

  // Update memory
  for (size_t i = 0; i < change.memoryAddresses.size(); i++) {
    const auto& target = change.memoryAddresses[i];
    const auto& data = change.memoryAddressValues[i];

    dataMemory_.requestWrite(target, data);
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
  return ticks_ / (clockFrequency / 1e9);
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

  std::vector<uint64_t> euCycles;

  // Sum up the branch stats reported across the execution units.
  for (auto& eu : executionUnits_) {
    totalBranchesExecuted += eu.getBranchExecutedCount();
    totalBranchMispredicts += eu.getBranchMispredictedCount();
    euCycles.push_back(eu.getCycles());
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
          {"eu0.cycles", std::to_string(euCycles[0])},
          {"eu1.cycles", std::to_string(euCycles[1])},
          {"eu2.cycles", std::to_string(euCycles[2])},
          {"eu3.cycles", std::to_string(euCycles[3])},
          {"eu4.cycles", std::to_string(euCycles[4])},
          {"eu5.cycles", std::to_string(euCycles[5])},
          {"eu6.cycles", std::to_string(euCycles[6])},
          {"eu7.cycles", std::to_string(euCycles[7])},
          {"memory.cycles", std::to_string(dataMemory_.getCycles())}};
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
