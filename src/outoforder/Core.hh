#pragma once

#include "../Core.hh"

#include "../pipeline/ExecuteUnit.hh"
#include "../pipeline/FetchUnit.hh"
#include "../pipeline/WritebackUnit.hh"
#include "DecodeUnit.hh"
#include "DispatchIssueUnit.hh"
#include "LoadStoreQueue.hh"
#include "PortAllocator.hh"
#include "RegisterAliasTable.hh"
#include "RenameUnit.hh"
#include "ReorderBuffer.hh"

namespace simeng {
namespace outoforder {

/** An out-of-order pipeline core model. Provides a 6-stage pipeline: Fetch,
 * Decode, Rename, Dispatch/Issue, Execute, Writeback. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing the process memory, and an ISA, branch
   * predictor, and port allocator to use. */
  Core(const span<char> processMemory, uint64_t entryPoint,
       const Architecture& isa, BranchPredictor& branchPredictor,
       PortAllocator& portAllocator);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Raise an exception to the core, providing the generating instruction. */
  void raiseException(std::shared_ptr<Instruction> instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Inspect units and flush pipelines if required. */
  void flushIfNeeded();

  const Architecture& isa;

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
  pipeline::FetchUnit fetchUnit;

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
  std::vector<pipeline::ExecuteUnit> executionUnits;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks = 0;

  /** Whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** Whether the core has halted. */
  bool hasHalted_ = false;
};

}  // namespace outoforder
}  // namespace simeng
