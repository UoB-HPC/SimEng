#include "Core.hh"

#include <algorithm>
#include <iostream>
#include <string>

// Temporary; until config options are available
#include "../../A64Instruction.hh"

namespace simeng {
namespace models {
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
Core::Core(const span<char> processMemory, uint64_t entryPoint,
           const Architecture& isa, BranchPredictor& branchPredictor,
           pipeline::PortAllocator& portAllocator)
    : isa_(isa),
      registerFileSet_(physicalRegisterStructures),
      registerAliasTable_(isa.getRegisterFileStructures(),
                          physicalRegisterQuantities),
      loadStoreQueue_(loadQueueSize, storeQueueSize, processMemory.data()),
      reorderBuffer_(robSize, registerAliasTable_, loadStoreQueue_,
                     [this](auto instruction) { raiseException(instruction); }),
      fetchToDecodeBuffer_(frontendWidth, {}),
      decodeToRenameBuffer_(frontendWidth, nullptr),
      renameToDispatchBuffer_(frontendWidth, nullptr),
      issuePorts_(executionUnitCount, {1, nullptr}),
      completionSlots_(executionUnitCount, {1, nullptr}),
      fetchUnit_(fetchToDecodeBuffer_, processMemory.data(),
                 processMemory.size(), entryPoint, isa, branchPredictor),
      decodeUnit_(fetchToDecodeBuffer_, decodeToRenameBuffer_, branchPredictor),
      renameUnit_(decodeToRenameBuffer_, renameToDispatchBuffer_,
                  reorderBuffer_, registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities, rsSize),
      writebackUnit_(completionSlots_, registerFileSet_) {
  for (size_t i = 0; i < executionUnitCount; i++) {
    executionUnits_.emplace_back(
        issuePorts_[i], completionSlots_[i],
        [this](auto regs, auto values) {
          dispatchIssueUnit_.forwardOperands(regs, values);
        },
        [this](auto uop) { loadStoreQueue_.startLoad(uop); },
        [this](auto uop) {}, [this](auto uop) { uop->setCommitReady(); },
        branchPredictor);
  }
};

void Core::tick() {
  ticks_++;

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
  }

  flushIfNeeded();
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
    decodeToRenameBuffer_.fill(nullptr);
    renameToDispatchBuffer_.fill(nullptr);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer_.flush(lowestSeqId);
    dispatchIssueUnit_.purgeFlushed();
    loadStoreQueue_.purgeFlushed();

    flushes_++;
  } else if (decodeUnit_.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    targetAddress = decodeUnit_.getFlushAddress();

    fetchUnit_.updatePC(targetAddress);
    fetchToDecodeBuffer_.fill({});

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

void Core::raiseException(const std::shared_ptr<Instruction>& instruction) {
  exceptionGenerated_ = true;
  exceptionGeneratingInstruction_ = instruction;
}

void Core::handleException() {
  exceptionGenerated_ = false;
  hasHalted_ = true;
  isa_.handleException(exceptionGeneratingInstruction_);
  std::cout << "Halting due to fatal exception" << std::endl;
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit_.getInstructionsWrittenCount();
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
  auto outOfOrderIssues = dispatchIssueUnit_.getOutOfOrderIssueCount();
  auto portBusyStalls = dispatchIssueUnit_.getPortBusyStalls();

  return {{"cycles", std::to_string(ticks_)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
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
          {"issue.outOfOrderIssues", std::to_string(outOfOrderIssues)},
          {"issue.portBusyStalls", std::to_string(portBusyStalls)}};
}

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
