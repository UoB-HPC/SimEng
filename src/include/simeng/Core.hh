#pragma once

#include <iostream>
#include <map>
#include <string>

#include "yaml-cpp/yaml.h"

namespace simeng {

class ArchitecturalRegisterFileSet;

/** An abstract core model. */
class Core {
 public:
  virtual ~Core() {}

  /** Tick the core. */
  virtual void tick() = 0;

  /** Check whether the program has halted. */
  virtual bool hasHalted() const = 0;

  /** Retrieve the architectural register file set. */
  virtual const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const = 0;

  /** Retrieve the number of instructions retired. */
  virtual uint64_t getInstructionsRetiredCount() const = 0;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  virtual uint64_t getSystemTimer() const = 0;

  /** Retrieve a map of statistics to report. */
  virtual std::map<std::string, std::string> getStats() const = 0;

  int windowSize = 0;
  float offsetPercentage = 0;
  int cyclesThroughWindow = windowSize * offsetPercentage;
  std::vector<uint64_t> longestCPinWindow;
};

}  // namespace simeng
