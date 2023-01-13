#pragma once

#include <iostream>
#include <map>
#include <string>

#include "simeng/kernel/Process.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {

class ArchitecturalRegisterFileSet;

enum CoreStatus : uint8_t { halted, idle, executing, exception };

/** An abstract core model. */
class Core {
 public:
  virtual ~Core() {}

  /** Tick the core. */
  virtual void tick() = 0;

  /** Check the current status of the core. */
  virtual CoreStatus getStatus() = 0;

  /** Retrieve the architectural register file set. */
  virtual const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const = 0;

  /** Retrieve the number of instructions retired. */
  virtual uint64_t getInstructionsRetiredCount() const = 0;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  virtual uint64_t getSystemTimer() const = 0;

  /** Retrieve a map of statistics to report. */
  virtual std::map<std::string, std::string> getStats() const = 0;

  /** Schedule a new Process. */
  virtual void schedule(std::shared_ptr<simeng::kernel::Process> newProc) = 0;

  /** Signals core to stop executing the current process.
   * Return Values :
   *  - True  : if succeeded in signaling interrupt
   *  - False : interrupt not scheduled due to on-going exception or system call
   */
  // virtual bool interrupt() = 0;
};

}  // namespace simeng
