#include "Core.hh"

#include <string>

namespace simeng {
namespace outoforder {

// TODO: Replace with config option
const std::initializer_list<uint16_t> physicalRegisters = {34, 34, 34};

// TODO: Replace simple process memory space with memory hierarchy interface.
Core::Core(const char* insnPtr, unsigned int programByteLength,
           const Architecture& isa, BranchPredictor& branchPredictor)
    : memory(static_cast<char*>(calloc(1024, 1))),
      registerFile(physicalRegisters),
      registerAliasTable(isa.getRegisterFileStructure(), physicalRegisters),
      reorderBuffer(16, registerAliasTable),
      fetchToDecodeBuffer(1, {}),
      decodeToRenameBuffer(1, nullptr),
      renameToDispatchBuffer(1, nullptr),
      issueToExecuteBuffer(1, nullptr),
      executeToWritebackBuffer(1, nullptr),
      fetchUnit(fetchToDecodeBuffer, insnPtr, programByteLength, isa,
                branchPredictor),
      decodeUnit(fetchToDecodeBuffer, decodeToRenameBuffer, branchPredictor),
      renameUnit(decodeToRenameBuffer, renameToDispatchBuffer, reorderBuffer,
                 registerAliasTable, physicalRegisters.size()),
      dispatchIssueUnit(renameToDispatchBuffer, issueToExecuteBuffer,
                        registerFile, physicalRegisters),
      executeUnit(issueToExecuteBuffer, executeToWritebackBuffer,
                  dispatchIssueUnit, branchPredictor, memory),
      writebackUnit(executeToWritebackBuffer, registerFile){};

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
  executeUnit.tick();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  fetchToDecodeBuffer.tick();
  decodeToRenameBuffer.tick();
  renameToDispatchBuffer.tick();
  issueToExecuteBuffer.tick();
  executeToWritebackBuffer.tick();

  // Commit a single instruction
  reorderBuffer.commit(1);

  // Check for flush
  if (executeUnit.shouldFlush()) {
    // Flush was requested at execute stage.
    // Update PC and wipe younger buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch, Issue/Execute)
    auto targetAddress = executeUnit.getFlushAddress();

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});
    decodeToRenameBuffer.fill(nullptr);
    renameToDispatchBuffer.fill(nullptr);
    issueToExecuteBuffer.fill(nullptr);

    // Flush everything younger than the bad instruction from the ROB
    reorderBuffer.flush(executeUnit.getFlushSeqId());

    flushes++;
  } else if (decodeUnit.shouldFlush()) {
    // Flush was requested at decode stage
    // Update PC and wipe Fetch/Decode buffer.
    auto targetAddress = decodeUnit.getFlushAddress();

    fetchUnit.updatePC(targetAddress);
    fetchToDecodeBuffer.fill({});

    flushes++;
  }
}

bool Core::hasHalted() const {
  // Core is considered to have halted when the fetch unit has halted, and there
  // are no uops at the head of any buffer.
  bool decodePending = fetchToDecodeBuffer.getHeadSlots()[0].size() > 0;
  bool renamePending = decodeToRenameBuffer.getHeadSlots()[0] != nullptr;
  bool commitPending = reorderBuffer.size() > 0;

  return (fetchUnit.hasHalted() && !decodePending && !renamePending &&
          !commitPending);
}

std::map<std::string, std::string> Core::getStats() const {
  auto retired = writebackUnit.getInstructionsRetiredCount();
  auto ipc = retired / static_cast<float>(ticks);
  return {{"cycles", std::to_string(ticks)},
          {"retired", std::to_string(retired)},
          {"ipc", std::to_string(ipc)},
          {"flushes", std::to_string(flushes)}};
}

}  // namespace outoforder
}  // namespace simeng
