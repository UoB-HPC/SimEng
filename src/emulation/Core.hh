#pragma once

#include "../Core.hh"

#include <map>
#include <string>

#include "../Architecture.hh"
#include "../RegisterFile.hh"

namespace simeng {
namespace emulation {

/** An emulation-style core model. Executes each instruction in turn. */
class Core : public simeng::Core {
 public:
  /** Construct an emulation-style core, providing an ISA
  to use, along with a pointer and size of instruction memory. */
  Core(const char* insnPtr, uint64_t programByteLength,
       const Architecture& isa);

  /** Tick the core. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** A pointer to process memory. */
  char* memory;

  /** Pointer to the start of instruction memory. */
  const char* insnPtr;

  /** The length of the available instruction memory. */
  uint64_t programByteLength;

  /** The currently used ISA. */
  const Architecture& isa;

  /** The current program counter. */
  uint64_t pc = 0;

  /** The core's register file. */
  RegisterFile registerFile;

  /** Whether or not the core has halted. */
  bool hasHalted_ = false;
};

}  // namespace emulation
}  // namespace simeng
