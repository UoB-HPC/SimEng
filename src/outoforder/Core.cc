#include "Core.hh"

#include <algorithm>
#include <string>

#include "PortAllocator.hh"

// Temporary; until config options are available
#include "../A64Instruction.hh"

namespace simeng {
namespace outoforder {

// TODO: Replace with config options
const std::initializer_list<uint16_t> physicalRegisterQuantities = {128, 128,
                                                                    128};
const std::initializer_list<RegisterFileStructure> physicalRegisterStructures =
    {{8, 128}, {16, 128}, {1, 128}};
const unsigned int robSize = 16;
const unsigned int rsSize = 16;
const unsigned int loadQueueSize = 16;
const unsigned int storeQueueSize = 8;
const unsigned int frontendWidth = 2;
const unsigned int commitWidth = 2;
const std::vector<std::vector<uint16_t>> portArrangement = {
    {A64InstructionGroups::LOAD, A64InstructionGroups::STORE},
    {A64InstructionGroups::ARITHMETIC},
    {A64InstructionGroups::BRANCH}};
const unsigned int executionUnitCount = portArrangement.size();

// TODO: Replace simple process memory space with memory hierarchy interface.
Core::Core(const char* insnPtr, unsigned int programByteLength,
           const Architecture& isa, BranchPredictor& branchPredictor,
           PortAllocator& portAllocator, char* memory)
    : registerFileSet(physicalRegisterStructures),
      registerAliasTable(isa.getRegisterFileStructures(),
                         physicalRegisterQuantities),
      loadStoreQueue(loadQueueSize, storeQueueSize, memory),
      reorderBuffer(robSize, registerAliasTable, loadStoreQueue),
      fetchToDecodeBuffer(frontendWidth, {}),
      decodeToRenameBuffer(frontendWidth, nullptr),
      renameToDispatchBuffer(frontendWidth, nullptr),
      issuePorts(executionUnitCount, {1, nullptr}),
      completionSlots(executionUnitCount, {1, nullptr}),
      fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa,
                branchPredictor),
      decodeUnit(fetchToDecodeBuffer, decodeToRenameBuffer, branchPredictor),
      renameUnit(decodeToRenameBuffer, renameToDispatchBuffer, reorderBuffer,
                 registerAliasTable, loadStoreQueue,
                 physicalRegisterStructures.size()),
      dispatchIssueUnit(renameToDispatchBuffer, issuePorts, registerFileSet,
                        portAllocator, physicalRegisterQuantities, rsSize),
      writebackUnit(completionSlots, registerFileSet) {
  for (size_t i = 0; i < executionUnitCount; i++) {
    executionUnits.emplace_back(issuePorts[i], completionSlots[i],
                                dispatchIssueUnit, loadStoreQueue,
                                branchPredictor);
  }
};

void Core::tick() {
  ticks++;

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit.tick();

  // Tick units
  fetchUnit.tick();
  decodeUnit.tick();
  renameUnit.tick();
  dispatchIssueUnit.tick();
  for (auto& eu : executionUnits) {
    // Tick each execution unit
    eu.tick();
  }

  // Late tick for the dispatch/issue unit to issue newly ready uops
  dispatchIssueUnit.issue();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer.tick();
  decodeToRenameBuffer.tick();
  renameToDispatchBuffer.tick();
  for (auto& issuePort : issuePorts) {
    issuePort.tick();
  }
  for (auto& completionSlot : completionSlots) {
    completionSlot.tick();
  }

  // Commit instructions from ROB
  reorderBuffer.commit(commitWidth);

  flushIfNeeded();
}

void Core::flushIfNeeded() {
  // Check for flush
  bool euFlush = false;
  uint64_t targetAddress = 0;
  uint64_t lowestSeqId = 0;
  for (const auto& eu : executionUnits) {
    if (eu.shouldFlush() && (!euFlush || eu.getFlushSeqId() < lowestSeqId)) {
      euFlush = true;
      lowestSeqId = eu.getFlushSeqId();
      targetAddress = eu.getFlushAddress();
    }
  }
  if (euFlush || reorderBuffer.shouldFlush()) {
    // Flush was requested in an out-of-order stage.
    // Update PC and wipe in-order buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch)

    if (reorderBuffer.shouldFlush() &&
        (!euFlush || reorderBuffer.getFlushSeqId() < lowestSeqId)) {
      // If the reorder buffer found an older instruction to flush up to, do
      // that instead
      lowestSeqId = reorderBuffer.getFlushSeqId();
      targetAddress = reorderBuffer.getFlushAddress();
    }

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});
    decodeToRenameBuffer.fill(nullptr);
    renameToDispatchBuffer.fill(nullptr);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer.flush(lowestSeqId);
    dispatchIssueUnit.purgeFlushed();
    loadStoreQueue.purgeFlushed();

    flushes++;
  } else if (decodeUnit.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    targetAddress = decodeUnit.getFlushAddress();

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});

    flushes++;
  }
}

bool Core::hasHalted() const {
  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
  if (!fetchUnit.hasHalted()) {
    return false;
  }

  if (reorderBuffer.size() > 0) {
    return false;
  }

  auto decodeSlots = fetchToDecodeBuffer.getHeadSlots();
  for (size_t slot = 0; slot < fetchToDecodeBuffer.getWidth(); slot++) {
    if (decodeSlots[slot].size() > 0) {
      return false;
    }
  }

  auto renameSlots = decodeToRenameBuffer.getHeadSlots();
  for (size_t slot = 0; slot < decodeToRenameBuffer.getWidth(); slot++) {
    if (renameSlots[slot] != nullptr) {
      return false;
    }
  }

  return true;
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit.getInstructionsRetiredCount();
  auto ipc = retired / static_cast<float>(ticks);

  auto branchStalls = fetchUnit.getBranchStalls();

  auto earlyFlushes = decodeUnit.getEarlyFlushes();

  auto allocationStalls = renameUnit.getAllocationStalls();
  auto robStalls = renameUnit.getROBStalls();
  auto lqStalls = renameUnit.getLoadQueueStalls();
  auto sqStalls = renameUnit.getStoreQueueStalls();

  auto rsStalls = dispatchIssueUnit.getRSStalls();
  auto frontendStalls = dispatchIssueUnit.getFrontendStalls();
  auto backendStalls = dispatchIssueUnit.getBackendStalls();
  auto outOfOrderIssues = dispatchIssueUnit.getOutOfOrderIssueCount();
  return {{"cycles", std::to_string(ticks)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
          {"flushes", std::to_string(flushes)},
          {"fetch.branchStalls", std::to_string(branchStalls)},
          {"decode.earlyFlushes", std::to_string(earlyFlushes)},
          {"rename.allocationStalls", std::to_string(allocationStalls)},
          {"rename.robStalls", std::to_string(robStalls)},
          {"rename.lqStalls", std::to_string(lqStalls)},
          {"rename.sqStalls", std::to_string(sqStalls)},
          {"dispatch.rsStalls", std::to_string(rsStalls)},
          {"issue.frontendStalls", std::to_string(frontendStalls)},
          {"issue.backendStalls", std::to_string(backendStalls)},
          {"issue.outOfOrderIssues", std::to_string(outOfOrderIssues)}};
}

}  // namespace outoforder
}  // namespace simeng
