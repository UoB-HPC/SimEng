#pragma once

#include <map>
#include <string>

namespace simeng {

/** An abstract core model. */
class Core {
 public:
  ~Core() {}

  /** Tick the core. */
  virtual void tick() = 0;

  /** Check whether the program has halted. */
  virtual bool hasHalted() const = 0;

  /** Retrieve a map of statistics to report. */
  virtual std::map<std::string, std::string> getStats() const = 0;
};

}  // namespace simeng
