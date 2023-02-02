#pragma once

#include <vector>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/riscv/ExceptionHandler.hh"
#include "simeng/pipeline/DecodeUnit.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace inorder {

/** A simple scalar in-order pipelined core model. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use,
   * along with a pointer and size of instruction memory, and a pointer to
   * process memory. */
  Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
       const arch::Architecture& isa, BranchPredictor& branchPredictor,
       std::function<void(const simeng::OS::SyscallInfo)> syscallHandle,
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

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Send a syscall to the system syscall handler. */
  void sendSyscall(const OS::SyscallInfo syscallInfo) const override;

  /** Communicate the result of a syscall to the core's active exception
   * handler. */
  void recieveSyscallResult(OS::SyscallResult result) const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

  /** Schedule a new Process. */
  void schedule(simeng::OS::cpuContext newContext) override;

  /** Signals core to stop executing the current process.
   * Return Values :
   *  - True  : if succeeded in signaling interrupt
   *  - False : interrupt not scheduled due to on-going exception or system call
   */
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

  /** Load and supply memory data requested by an instruction. */
  void loadData(const std::shared_ptr<Instruction>& instruction);
  /** Store data supplied by an instruction to memory. */
  void storeData(const std::shared_ptr<Instruction>& instruction);

  /** Forward operands to the most recently decoded instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

  /** Read pending registers for the most recently decoded instruction. */
  void readRegisters();

  /** Process the active exception. */
  void processException();

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

  /** Handle requesting/execution of a load instruction. */
  void handleLoad(const std::shared_ptr<Instruction>& instruction);

  /** The current state the core is in. */
  CoreStatus status_ = CoreStatus::idle;

  /** The process memory. */
  MemoryInterface& dataMemory_;

  /** A reference to the core's architecture. */
  const arch::Architecture& isa_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around the
   * register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** The buffer between fetch and decode. */
  pipeline::PipelineBuffer<MacroOp> fetchToDecodeBuffer_;

  /** The buffer between decode and execute. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>> decodeToExecuteBuffer_;

  /** The buffer between execute and writeback. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots_;

  /** The previously generated addresses. */
  std::queue<simeng::MemoryAccessTarget> previousAddresses_;

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit_;

  /** The decode unit; decodes instructions into uops and reads operands. */
  pipeline::DecodeUnit decodeUnit_;

  /** The execute unit; executes uops and sends to writeback, also forwarding
   * results. */
  pipeline::ExecuteUnit executeUnit_;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit_;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes_ = 0;

  /** The total number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** The number of times this core has ticked whilst executing the current
   * process. */
  uint64_t procTicks_ = 0;

  /** Whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** The active exception handler. */
  std::unique_ptr<ExceptionHandler> exceptionHandler_;

  /** Function to communicate a syscall generated by the exception handler out
   * of the Core class and to the system's syscall handler.*/
  std::function<void(const simeng::OS::SyscallInfo)> syscallHandle_;

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
