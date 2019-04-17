#pragma once

#include <tuple>
#include <vector>

#include "BranchPredictor.hh"
#include "Instruction.hh"
#include "RegisterFileSet.hh"

namespace simeng {

using MacroOp = std::vector<std::shared_ptr<Instruction>>;

/** A structure describing a set of changes to the process state. */
struct ProcessStateChange {
  /** Registers to modify */
  std::vector<Register> modifiedRegisters;
  /** Values to set modified registers to */
  std::vector<RegisterValue> modifiedRegisterValues;
  /** Memory address/width pairs to modify */
  std::vector<std::pair<uint64_t, uint8_t>> memoryAddresses;
  /** Values to write to memory */
  std::vector<RegisterValue> memoryAddressValues;
};

/** An abstract Instruction Set Architecture (ISA) definition. Each supported
 * ISA should provide a derived implementation of this class. */
class Architecture {
 public:
  virtual ~Architecture(){};

  /** Attempt to pre-decode from `bytesAvailable` bytes of instruction memory.
   * Writes into the supplied macro-op vector, and returns the number of bytes
   * consumed to produce it; a value of 0 indicates too few bytes were present
   * for a valid decoding. */
  virtual uint8_t predecode(const void* ptr, uint8_t bytesAvailable,
                            uint64_t instructionAddress,
                            BranchPrediction prediction,
                            MacroOp& output) const = 0;

  /** Returns a vector of {size, number} pairs describing the available
   * registers. */
  virtual std::vector<RegisterFileStructure> getRegisterFileStructures()
      const = 0;

  virtual void handleException(
      const std::shared_ptr<Instruction>& instruction) const = 0;

  /** Retrieve the initial process state for the supplied process memory. */
  virtual ProcessStateChange getInitialState(
      span<char> processMemory) const = 0;

  /** Determine whether the specified register can be renamed. */
  virtual bool canRename(Register reg) const = 0;
};

}  // namespace simeng
