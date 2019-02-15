#pragma once

#include <tuple>
#include <vector>

#include "BranchPredictor.hh"
#include "Instruction.hh"
#include "RegisterFile.hh"

namespace simeng {

using MacroOp = std::vector<std::shared_ptr<Instruction>>;

/** An abstract Instruction Set Architecture (ISA) definition. Each supported
 * ISA should provide a derived implementation of this class. */
class Architecture {
 public:
  virtual ~Architecture(){};

  /** Attempt to pre-decode from `bytesAvailable` bytes of instruction memory.
   * Returns the macro-op generated and the number of bytes consumed to produce
   * it; a value of 0 indicates too few bytes were present for a valid decoding.
   */
  virtual std::tuple<MacroOp, uint8_t> predecode(
      const void* ptr, uint8_t bytesAvailable, uint64_t instructionAddress,
      BranchPrediction prediction) const = 0;

  /** Returns a vector of {size, number} pairs describing the available
   * registers. */
  virtual std::vector<RegisterFileStructure> getRegisterFileStructure()
      const = 0;

  /** Determine whether the specified register can be renamed. */
  virtual bool canRename(Register reg) const = 0;
};

}  // namespace simeng
