#pragma once

#include <map>
#include <queue>
#include <string>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/span.hh"

namespace simeng {
namespace models {
namespace emulation {

/** An emulation-style core model. Executes each instruction in turn. */
class Core : public simeng::Core {
 public:
  /** Construct an emulation-style core, providing memory interfaces for
   * instructions and data, along with the instruction entry point and an ISA to
   * use. */
  Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
       const arch::Architecture& isa);

  /** Tick the core. */
  void tick() override;

  /** Check the current status of the core. */
  CoreStatus getStatus() override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  uint64_t getSystemTimer() const override;

  /** Retrieve a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

  /** Schedule a new Process. */
  void schedule(simeng::kernel::cpuContext newContext) override;

  /** Signals core to stop executing the current process.
   * Return Values :
   *  - True  : if succeeded in signaling interrupt
   *  - False : interrupt not scheduled due to on-going exception or system call
   */
  bool interrupt() override;

  /** Retrieve the number of ticks that have elapsed whilst executing the
   * current process. */
  uint64_t getCurrentProcTicks() const override;

  /** Retrieve the current CPU context for the currently executing / outgoing
   * process. */
  simeng::kernel::cpuContext getPrevContext() const override;

 private:
  /** Execute an instruction. */
  void execute(std::shared_ptr<Instruction>& uop);

  /** Handle an encountered exception. */
  void handleException(const std::shared_ptr<Instruction>& instruction);

  /** Process an active exception handler. */
  void processExceptionHandler();

  /** Apply changes to the process state. */
  void applyStateChange(const arch::ProcessStateChange& change);

  /** The current state the core is in. */
  CoreStatus status_ = CoreStatus::idle;

  /** A memory interface to access instructions. */
  MemoryInterface& instructionMemory_;

  /** A memory interface to access data. */
  MemoryInterface& dataMemory_;

  /** The previously generated addresses. */
  std::vector<simeng::MemoryAccessTarget> previousAddresses_;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_ = 0;

  /** The currently used ISA. */
  const arch::Architecture& isa_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around the
   * register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** A reusable macro-op vector to fill with uops. */
  MacroOp macroOp_;

  /** An internal buffer for storing one or more uops. */
  std::queue<std::shared_ptr<Instruction>> microOps_;

  /** The active exception handler. */
  std::shared_ptr<arch::ExceptionHandler> exceptionHandler_;

  /** Is the core waiting on a data read? */
  unsigned int pendingReads_ = 0;

  /** The total number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** The number of times this core has ticked whilst executing the current
   * process. */
  uint64_t procTicks_ = 0;

  /** The number of instructions executed. */
  uint64_t instructionsExecuted_ = 0;

  /** The number of branches executed. */
  uint64_t branchesExecuted_ = 0;

  /** The number of ticks whilst in an idle state. */
  uint64_t idle_ticks_ = 0;

  /** Number of times a context switch was performed. */
  uint64_t contextSwitches_ = 0;

  /** TID of process core is currently executing. */
  uint64_t currentTID_;
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
