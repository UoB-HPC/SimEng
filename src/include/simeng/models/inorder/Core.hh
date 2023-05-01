#pragma once

#include <vector>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/riscv/ExceptionHandler.hh"
#include "simeng/pipeline/BlockingIssueUnit.hh"
#include "simeng/pipeline/DecodeUnit.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/InOrderStager.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace inorder {

/** A simple scalar in-order pipelined core model. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA, branch predictor, mmu, and port
   * allocator to use, along with a handler to raise a syscall. */
  Core(const arch::Architecture& isa, BranchPredictor& branchPredictor,
       std::shared_ptr<memory::MMU> mmu, pipeline::PortAllocator& portAllocator,
       arch::sendSyscallToHandler handleSyscall,
       ryml::Tree config = config::SimInfo::getConfig());

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
  void raiseException(const std::shared_ptr<Instruction>& insn);

  /** Handle an exception raised during the cycle. */
  bool handleException();

  /** A function to query whether the instruction associated with the passed
   * sequence ID can writeback its results. */
  bool canWriteback(uint64_t seqId);

  /** A function to carry out logic associated with the retirement of a
   * instruction post writeback. */
  void retireInstruction(const std::shared_ptr<Instruction>& insn);

  /** Forward operands to the most recently decoded instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

  /** Process the active exception. */
  void processException();

  /** Create an instance of the exception handler based on the chosen
   * architecture. */
  void exceptionHandlerFactory(config::ISA isa) {
    if (isa == config::ISA::AArch64)
      exceptionHandler_ =
          std::make_unique<simeng::arch::aarch64::ExceptionHandler>(*this);
    else if (isa == config::ISA::RV64)
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

  /** The Core's Memory Management Unit. */
  std::shared_ptr<memory::MMU> mmu_;

  /** A reference to the core's architecture. */
  const arch::Architecture& isa_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around
   * the register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** The buffer between fetch and decode. */
  pipeline::PipelineBuffer<MacroOp> fetchToDecodeBuffer_;

  /** The buffer between decode and execute. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>> decodeToIssueBuffer_;

  /** The issue ports; single-width buffers between issue and execute. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      issuePorts_;

  /** The buffer between execute and writeback. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots_;

  /** The core's load/store queue. */
  pipeline::LoadStoreQueue loadStoreQueue_;

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit_;

  /** The decode unit; decodes instructions into uops and reads operands. */
  pipeline::DecodeUnit decodeUnit_;

  /** The inorder stager unit; tracks in program-order instructions issued to
   * ensure writeback functionality occurs in program-order. */
  pipeline::InOrderStager staging_;

  /** The issue unit; reads operands, and issues ready instructions to the
   * execution unit in program-order. */
  pipeline::BlockingIssueUnit issueUnit_;

  /** The set of execution units; executes uops and sends to writeback, also
   * forwarding results to issue. */
  std::vector<pipeline::ExecuteUnit> executionUnits_;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit_;

  /** The port allocator unit; allocates a port that an instruction will be
   * issued from based on a defined algorithm. */
  pipeline::PortAllocator& portAllocator_;

  /** A queue of store address uops that have been retired. Future store
   * data uops can use this queue to commit its associated store macro-op in the
   * core's load/store queue unit.
   */
  std::queue<std::shared_ptr<Instruction>> completedStoreAddrUops_ = {};

  /** Whether a store is actively being processed and not yet ready for
   * commitment. */
  bool activeStore_ = false;

  /** Whether a load vioaltion has been detected by the load store queue. */
  bool loadViolation_ = false;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes_ = 0;

  /** The number of load violations detected in the load store queue. */
  uint64_t loadViolations_ = 0;

  /** The total number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** The number of times this core has ticked whilst executing the current
   * process. */
  uint64_t procTicks_ = 0;

  /** Indicates whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** Indicates whether an excpetion has been registered with the core's
   * exception handler. */
  bool exceptionRegistered_ = false;

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

}  // namespace inorder
}  // namespace models
}  // namespace simeng
