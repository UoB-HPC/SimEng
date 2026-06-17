#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/OS/SyscallHandler.hh"

namespace simeng {
namespace arch {

/** Typedef for callback function used to send a generated syscall to the
 * simulated Operating System's syscall handler. */
typedef std::function<void(simeng::OS::SyscallInfo)> sendSyscallToHandler;

/** The result from a handled exception. */
struct ExceptionResult {
  /** Indicates whether the outcome of the exception is fatal for the associated
   * core and it should therefore halt. */
  bool fatal;

  /** Indicates whether the receiving core should go into an idle state after
   * the syscall has concluded and all state changes have been processed. */
  bool idleAfterSyscall = false;

  /** The address to resume execution from. */
  uint64_t instructionAddress;

  /** Any changes to apply to the process state. */
  simeng::OS::ProcessStateChange stateChange = {};
};

/** An abstract multi-cycle exception handler interface. Should be ticked each
 * cycle until complete. */
class ExceptionHandler {
 public:
  virtual ~ExceptionHandler(){};

  /** Tick the exception handler to progress handling of the exception. Should
   * return `false` if the exception requires further handling, or `true` once
   * complete. */
  virtual bool tick() = 0;

  /** Register the instruction which contains the exception with the exception
   * handler. */
  virtual void registerException(
      std::shared_ptr<simeng::Instruction> instruction) = 0;

  /** Process the result of a syscall from the SyscallHandler. */
  virtual void processSyscallResult(
      const simeng::OS::SyscallResult syscallResult) = 0;

  /** Retrieve the result of the exception. */
  virtual const ExceptionResult& getResult() const = 0;
};

}  // namespace arch
}  // namespace simeng
