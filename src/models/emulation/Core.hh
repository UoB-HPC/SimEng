#pragma once

#include "../../Core.hh"

#include <map>
#include <string>

#include "../../Architecture.hh"
#include "../../RegisterFileSet.hh"
#include "../../span.hh"

namespace simeng {
namespace models {
namespace emulation {

/** An emulation-style core model. Executes each instruction in turn. */
class Core : public simeng::Core {
 public:
  /** Construct an emulation-style core, providing an ISA
  to use, along with a pointer and size of instruction memory, and a pointer to
  process memory. */
  Core(const span<char> processMemory, uint64_t entryPoint,
       const Architecture& isa);

  /** Tick the core. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Handle an encountered exception. */
  void handleException(const std::shared_ptr<Instruction>& instruction);

  /** A pointer to process memory. */
  char* memory_;

  /** Pointer to the start of instruction memory. */
  const char* insnPtr_;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_;

  /** The currently used ISA. */
  const Architecture& isa_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** Whether or not the core has halted. */
  bool hasHalted_ = false;

  /** A reusable macro-op vector to fill with uops. */
  MacroOp macroOp_;
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
