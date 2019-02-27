#pragma once

#include "../Core.hh"

#include "DecodeUnit.hh"
#include "DispatchIssueUnit.hh"
#include "ExecuteUnit.hh"
#include "FetchUnit.hh"
#include "LoadStoreQueue.hh"
#include "PortAllocator.hh"
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
  /** Construct a core model, providing an ISA, branch predictor, and port
   * allocator to use, along with a pointer and size of instruction memory, and
   * a pointer to process memory. */
  Core(const char* insnPtr, unsigned int programByteLength,
       const Architecture& isa, BranchPredictor& branchPredictor,
       PortAllocator& portAllocator, char* memory);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Inspect units and flush pipelines if required. */
  void flushIfNeeded();

  /** The core's register file set. */
  RegisterFileSet registerFileSet;

  /** The core's register alias table. */
  RegisterAliasTable registerAliasTable;

  /** The core's load/store queue. */
  LoadStoreQueue loadStoreQueue;

  /** The core's reorder buffer. */
  ReorderBuffer reorderBuffer;

  /** The buffer between fetch and decode. */
  PipelineBuffer<MacroOp> fetchToDecodeBuffer;

  /** The buffer between decode and rename. */
  PipelineBuffer<std::shared_ptr<Instruction>> decodeToRenameBuffer;

  /** The buffer between rename and dispatch/issue. */
  PipelineBuffer<std::shared_ptr<Instruction>> renameToDispatchBuffer;

  /** The issue ports; single-width buffers between issue and execute. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> issuePorts;

  /** The completion slots; single-width buffers between execute and writeback.
   */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots;

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

  /** The set of execution units; executes uops and sends to writeback, also
   * forwarding results to dispatch/issue. */
  std::vector<ExecuteUnit> executionUnits;

  /** The writeback unit; writes uop results to the register files. */
  WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks = 0;
};

}  // namespace outoforder
}  // namespace simeng
