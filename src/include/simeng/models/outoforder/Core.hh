#pragma once

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Config.hh"
#include "simeng/Core.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/riscv/ExceptionHandler.hh"
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
  Core(const arch::Architecture& isa, BranchPredictor& branchPredictor,
       std::shared_ptr<memory::MMU> mmu, pipeline::PortAllocator& portAllocator,
       arch::sendSyscallToHandler handleSyscall,
       YAML::Node& config = Config::get());

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check the current status of the core. */
  CoreStatus getStatus() override;

  /** Update the current status of the core. */
  void setStatus(CoreStatus newStatus) override;

  /** Get the TID of the Process the core is currently executing. */
  uint64_t getCurrentTID() const override;

  /** Get the unqiue id of the core. */
  uint64_t getCoreId() const override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** A function to carry out post-writeback micro-op commit logic. */
  void microOpWriteback(const std::shared_ptr<Instruction>& insn);

  /** Send a syscall to the simulated Operating System's syscall handler. */
  void sendSyscall(OS::SyscallInfo syscallInfo) const override;

  /** This method receives the result of an initiated syscall and communicates
   * the result to the exception handler for post-processing. */
  void receiveSyscallResult(const OS::SyscallResult result) const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

  /** Schedule a new Process. */
  void schedule(simeng::OS::cpuContext newContext) override;

  /** Signals core to stop executing the current process.
   * Return Values :
   *  - True  : if succeeded in signaling interrupt
   *  - False : interrupt not scheduled due to on-going exception or system
   * call */
  bool interrupt() override;

  /** Retrieve the number of ticks that have elapsed whilst executing the
   * current process. */
  uint64_t getCurrentProcTicks() const override;

  /** Retrieve the CPU context for the currently scheduled process. */
  simeng::OS::cpuContext getCurrentContext() const override;

 private:
  /** Raise an exception to the core, providing the generating instruction. */
  void raiseException(const std::shared_ptr<Instruction>& instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Process the active exception. */
  void processException();

  /** Create an instance of the exception handler based on the chosen
   * architecture. */
  void exceptionHandlerFactory(std::string isa) {
    if (isa == "AArch64")
      exceptionHandler_ =
          std::make_unique<simeng::arch::aarch64::ExceptionHandler>(*this);
    else if (isa == "rv64")
      exceptionHandler_ =
          std::make_unique<simeng::arch::riscv::ExceptionHandler>(*this);
  }

  /** Apply changes to the process state. */
  void applyStateChange(const OS::ProcessStateChange& change);

  /** Inspect units and flush pipelines if required. */
  void flushIfNeeded();

  /** The current state the core is in. */
  CoreStatus status_ = CoreStatus::idle;

  /** Unique identifier for the core. */
  // TODO: Unqiue IDs need to be assigned to the cores when we go
  // multicore
  uint64_t coreId_ = 0;

  /** A reference to the core's architecture. */
  const arch::Architecture& isa_;

  /** The layout of the physical register file sets. */
  const std::vector<simeng::RegisterFileStructure> physicalRegisterStructures_;

  /** The size of each regsiter file. */
  const std::vector<uint16_t> physicalRegisterQuantities_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** The core's register alias table. */
  pipeline::RegisterAliasTable registerAliasTable_;

  /** The mapped register file set. */
  pipeline::MappedRegisterFileSet mappedRegisterFileSet_;

  /** The Core's Memory Management Unit. */
  std::shared_ptr<memory::MMU> mmu_;

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

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit_;

  /** The core's reorder buffer. */
  pipeline::ReorderBuffer reorderBuffer_;

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

  /** Core commit width; maximum number of instruction that can be committed
   * per cycle. */
  unsigned int commitWidth_ = 6;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes_ = 0;

  /** The total number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** The number of times this core has ticked whilst executing the current
   * process. */
  uint64_t procTicks_ = 0;

  /** Indicates whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** The active exception handler. */
  std::unique_ptr<arch::ExceptionHandler> exceptionHandler_;

  /** Callback function passed to the Core class to communicate a syscall
   * generated by the Core's exception handler to the simulated Operating
   * System's syscall handler. */
  arch::sendSyscallToHandler handleSyscall_;

  /** The number of ticks whilst in an idle state. */
  uint64_t idle_ticks_ = 0;

  /** Number of times a context switch was performed. */
  uint64_t contextSwitches_ = 0;

  /** TID of the process currently executing on the core. */
  uint64_t currentTID_ = -1;
};

}  // namespace outoforder
}  // namespace models
}  // namespace simeng
