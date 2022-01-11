#pragma once

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/pipeline/DecodeUnit.hh"
#include "simeng/pipeline/DispatchIssueUnit.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/MappedRegisterFileSet.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/PortAllocator.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"
#include "simeng/pipeline/RenameUnit.hh"
#include "simeng/pipeline/ReorderBuffer.hh"
#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace outoforder {

/** An out-of-order pipeline core model. Provides a 6-stage pipeline: Fetch,
 * Decode, Rename, Dispatch/Issue, Execute, Writeback. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing the process memory, and an ISA, branch
   * predictor, and port allocator to use. */
  Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
       uint64_t processMemorySize, uint64_t entryPoint,
       const arch::Architecture& isa, BranchPredictor& branchPredictor,
       pipeline::PortAllocator& portAllocator,
       const std::vector<std::pair<uint8_t, uint64_t>>& rsArrangment,
       YAML::Node config);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  uint64_t getSystemTimer() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Raise an exception to the core, providing the generating instruction. */
  void raiseException(const std::shared_ptr<Instruction>& instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Process the active exception handler. */
  void processExceptionHandler();

  /** Apply changes to the process state. */
  void applyStateChange(const arch::ProcessStateChange& change);

  /** Inspect units and flush pipelines if required. */
  void flushIfNeeded();

  const arch::Architecture& isa_;

  const std::vector<simeng::RegisterFileStructure> physicalRegisterStructures_;

  const std::vector<uint16_t> physicalRegisterQuantities_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** The core's register alias table. */
  pipeline::RegisterAliasTable registerAliasTable_;

  /** The mapped register file set. */
  pipeline::MappedRegisterFileSet mappedRegisterFileSet_;

  /** The process memory. */
  MemoryInterface& dataMemory_;

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

  /** The core's load/store queue. */
  pipeline::LoadStoreQueue loadStoreQueue_;

  /** The core's reorder buffer. */
  pipeline::ReorderBuffer reorderBuffer_;

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

  /** The port allocator unit; allocates a port that an instruction will be
   * issued from based on a defined algorithm. */
  pipeline::PortAllocator& portAllocator_;

  /** Clock frequency of core */
  unsigned int clockFrequency_ = 2.5 * 1e9;

  /** Core commit width; maximum number of instruction that can be committed per
   * cycle. */
  unsigned int commitWidth_ = 6;

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

  /** The active exception handler. */
  std::shared_ptr<arch::ExceptionHandler> exceptionHandler_;
};

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
