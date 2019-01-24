#pragma once

#include <vector>
#include <tuple>

#include "Instruction.hh"

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
      void* ptr, uint8_t bytesAvailable, uint64_t instructionAddress) const = 0;

  /** Returns a vector of {size, number} pairs describing the available
   * registers. */
  virtual std::vector<std::pair<uint8_t, uint16_t>> getRegisterFileStructure()
      const = 0;
  virtual bool canRename(Register reg) const = 0;
};

}  // namespace simeng
