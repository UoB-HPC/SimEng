#pragma once

#include <map>
#include <queue>
#include <string>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/ExceptionHandler.hh"
#include "simeng/arch/riscv/ExceptionHandler.hh"
#include "simeng/memory/MMU.hh"
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
  Core(const arch::Architecture& isa, std::shared_ptr<memory::MMU> mmu,
       arch::sendSyscallToHandler handleSyscall,
       std::function<void(OS::cpuContext, uint16_t, CoreStatus, uint64_t)>);

  /** Tick the core. */
  void tick() override;

  /** Check the current status of the core. */
  CoreStatus getStatus() override;

  /** Update the current status of the core. */
  void setStatus(CoreStatus newStatus) override;

  /** Get the TID of the Process the core is currently executing. */
  uint64_t getCurrentTID() const override;

  /** Get the unqiue id of the core. */
  uint16_t getCoreId() const override;

  /** Set the unqiue id of the core. */
  void setCoreId(uint16_t id) override;

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

  /** Retrieve a map of statistics to report. */
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
  simeng::OS::cpuContext getCurrentContext(bool clearTID = false) override;

 private:
  /** Execute an instruction. */
  void execute(std::shared_ptr<Instruction>& uop);

  /** Handle an encountered exception. */
  void handleException(const std::shared_ptr<Instruction>& instruction);

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

  /** The current state the core is in. */
  CoreStatus status_ = CoreStatus::idle;

  /** Unique identifier for the core. */
  // TODO: Unqiue IDs need to be assigned to the cores when we go
  // multicore
  uint16_t coreId_ = 0;

  /** The Core's Memory Management Unit. */
  std::shared_ptr<memory::MMU> mmu_;

  /** The previously generated addresses. */
  std::vector<simeng::memory::MemoryAccessTarget> previousAddresses_;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_ = 0;

  /** The currently used ISA. */
  const arch::Architecture& isa_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** Whether or not a request for an instruction fetch is active. */
  bool waitingOnRead_ = false;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around
   * the register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** A reusable macro-op vector to fill with uops. */
  MacroOp macroOp_;

  /** An internal buffer for storing one or more uops. */
  std::queue<std::shared_ptr<Instruction>> microOps_;

  /** Indicates whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** The active exception handler. */
  std::unique_ptr<arch::ExceptionHandler> exceptionHandler_;

  /** Callback function passed to the Core class to communicate a syscall
   * generated by the Core's exception handler to the simulated Operating
   * System's syscall handler. */
  arch::sendSyscallToHandler handleSyscall_;

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

  /** TID of the process currently executing on the core. */
  uint64_t currentTID_ = -1;

  std::function<void(OS::cpuContext, uint16_t, CoreStatus, uint64_t)>
      updateCoreDescInOS_;

  /** The number of in-flight store-conditional requests. */
  uint64_t inFlightStoreCondReqs_ = 0;

  bool printing_ = false;
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
