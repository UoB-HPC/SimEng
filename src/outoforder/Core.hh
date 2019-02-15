#pragma once

#include "../Core.hh"

#include "DecodeUnit.hh"
#include "DispatchIssueUnit.hh"
#include "ExecuteUnit.hh"
#include "FetchUnit.hh"
#include "RegisterAliasTable.hh"
#include "RenameUnit.hh"
#include "ReorderBuffer.hh"
#include "WritebackUnit.hh"

namespace simeng {
namespace outoforder {

/** An out-of-order pipeline core model. Provides a 6-stage pipeline: Fetch,
 * Decode, Rename, Dispatch/Issue, Execute, Writeback. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use,
   * along with a pointer and size of instruction memory. */
  Core(const char* insnPtr, unsigned int programByteLength,
       const Architecture& isa, BranchPredictor& branchPredictor);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** A pointer to process memory. */
  char* memory;

  /** The core's register file. */
  RegisterFile registerFile;

  /** The core's register alias table. */
  RegisterAliasTable registerAliasTable;

  /** The core's reorder buffer. */
  ReorderBuffer reorderBuffer;

  /** The buffer between fetch and decode. */
  PipelineBuffer<MacroOp> fetchToDecodeBuffer;

  /** The buffer between decode and rename. */
  PipelineBuffer<std::shared_ptr<Instruction>> decodeToRenameBuffer;

  /** The buffer between rename and dispatch/issue. */
  PipelineBuffer<std::shared_ptr<Instruction>> renameToDispatchBuffer;

  /** The buffer between dispatch/issue and execute. */
  PipelineBuffer<std::shared_ptr<Instruction>> issueToExecuteBuffer;

  /** The buffer between execute and writeback. */
  PipelineBuffer<std::shared_ptr<Instruction>> executeToWritebackBuffer;

  /** The fetch unit; fetches instructions from memory. */
  FetchUnit fetchUnit;

  /** The decode unit; decodes instructions into uops and reads operands. */
  DecodeUnit decodeUnit;

  /** The rename unit; renames instruction registers. */
  RenameUnit renameUnit;

  /** The dispatch/issue unit; dispatches instructions to the reservation
   * station, reads operands, and issues ready instructions to the execution
   * unit. */
  DispatchIssueUnit dispatchIssueUnit;

  /** The execute unit; executes uops and sends to writeback, also forwarding
   * results to dispatch/issue. */
  ExecuteUnit executeUnit;

  /** The writeback unit; writes uop results to the register file. */
  WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks = 0;
};

}  // namespace outoforder
}  // namespace simeng
