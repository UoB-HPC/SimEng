#pragma once

#include "../../Core.hh"

#include "../../pipeline/DecodeUnit.hh"
#include "../../pipeline/DispatchIssueUnit.hh"
#include "../../pipeline/ExecuteUnit.hh"
#include "../../pipeline/FetchUnit.hh"
#include "../../pipeline/LoadStoreQueue.hh"
#include "../../pipeline/PipelineBuffer.hh"
#include "../../pipeline/PortAllocator.hh"
#include "../../pipeline/RegisterAliasTable.hh"
#include "../../pipeline/RenameUnit.hh"
#include "../../pipeline/ReorderBuffer.hh"
#include "../../pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace outoforder {

/** An out-of-order pipeline core model. Provides a 6-stage pipeline: Fetch,
 * Decode, Rename, Dispatch/Issue, Execute, Writeback. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing the process memory, and an ISA, branch
   * predictor, and port allocator to use. */
  Core(const span<char> processMemory, uint64_t entryPoint,
       const Architecture& isa, BranchPredictor& branchPredictor,
       pipeline::PortAllocator& portAllocator);

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
  void raiseException(const std::shared_ptr<Instruction>& instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Inspect units and flush pipelines if required. */
  void flushIfNeeded();

  const Architecture& isa_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** The core's register alias table. */
  pipeline::RegisterAliasTable registerAliasTable_;

  /** The core's load/store queue. */
  pipeline::LoadStoreQueue loadStoreQueue_;

  /** The core's reorder buffer. */
  pipeline::ReorderBuffer reorderBuffer_;

  /** The buffer between fetch and decode. */
  pipeline::PipelineBuffer<MacroOp> fetchToDecodeBuffer_;

  /** The buffer between decode and rename. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>> decodeToRenameBuffer_;

  /** The buffer between rename and dispatch/issue. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>>
      renameToDispatchBuffer_;

  /** The issue ports; single-width buffers between issue and execute. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      issuePorts_;

  /** The completion slots; single-width buffers between execute and writeback.
   */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots_;

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit_;

  /** The decode unit; decodes instructions into uops and reads operands. */
  pipeline::DecodeUnit decodeUnit_;

  /** The rename unit; renames instruction registers. */
  pipeline::RenameUnit renameUnit_;

  /** The dispatch/issue unit; dispatches instructions to the reservation
   * station, reads operands, and issues ready instructions to the execution
   * unit. */
  pipeline::DispatchIssueUnit dispatchIssueUnit_;

  /** The set of execution units; executes uops and sends to writeback, also
   * forwarding results to dispatch/issue. */
  std::vector<pipeline::ExecuteUnit> executionUnits_;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit_;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes_ = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** Whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** Whether the core has halted. */
  bool hasHalted_ = false;
};

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
