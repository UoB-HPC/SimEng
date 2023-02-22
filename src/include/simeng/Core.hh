#pragma once

#include <iostream>
#include <map>
#include <string>

#include "simeng/OS/Process.hh"
#include "simeng/OS/SyscallHandler.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {

class ArchitecturalRegisterFileSet;

/** Typedef for callback function used to send a generated syscall to the
 * simulated Operating System's syscall handler. */
typedef std::function<void(simeng::OS::SyscallInfo)> sendSyscallToHandler;

enum CoreStatus : uint8_t { halted, idle, executing, switching };

/** The result from a handled exception. */
struct ExceptionResult {
  /** Whether the outcome of the exception is fatal for the associated core and
   * it should therefore halt. */
  bool fatal;

  /** The address to resume execution from. */
  uint64_t instructionAddress;

  /** Any changes to apply to the process state. */
  simeng::OS::ProcessStateChange stateChange;
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
      simeng::OS::SyscallResult syscallResult) = 0;

  /** Retrieve the result of the exception. */
  virtual const ExceptionResult& getResult() const = 0;
};

/** The number of bytes fetched each cycle. */
#define FETCH_SIZE 4

/** An abstract core model. */
class Core {
 public:
  virtual ~Core() {}

  /** Tick the core. */
  virtual void tick() = 0;

  /** Check the current status of the core. */
  virtual CoreStatus getStatus() = 0;

  /** Update the current status of the core. */
  virtual void setStatus(CoreStatus newStatus) = 0;

  /** Get the TID of the Process the core is currently executing. */
  virtual uint64_t getCurrentTID() const = 0;

  /** Retrieve the architectural register file set. */
  virtual const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const = 0;

  /** Send a syscall to the simulated Operating System's syscall handler. */
  virtual void sendSyscall(OS::SyscallInfo) const = 0;

  /** This method receives the result of an initiated syscall and communicates
   * the result to the exception handler for post-processing. */
  virtual void receiveSyscallResult(const OS::SyscallResult result) const = 0;

  /** Retrieve the number of instructions retired. */
  virtual uint64_t getInstructionsRetiredCount() const = 0;

  /** Retrieve a map of statistics to report. */
  virtual std::map<std::string, std::string> getStats() const = 0;

  /** Schedule a new Process. */
  virtual void schedule(simeng::OS::cpuContext newContext) = 0;

  /** Signals core to stop executing the current process.
   * Return Values :
   *  - True  : if succeeded in signaling interrupt
   *  - False : interrupt not scheduled due to on-going exception or system
   * call */
  virtual bool interrupt() = 0;

  /** Retrieve the number of ticks that have elapsed whilst executing the
   * current process. */
  virtual uint64_t getCurrentProcTicks() const = 0;

  /** Retrieve the CPU context for the currently scheduled process. */
  virtual simeng::OS::cpuContext getCurrentContext() const = 0;
};

}  // namespace simeng
