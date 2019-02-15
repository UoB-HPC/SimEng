#pragma once

#include "Architecture.hh"

#include <unordered_map>

#include "A64Instruction.hh"

namespace simeng {

/* A basic ARMv8-a implementation of the `Architecture` interface. */
class A64Architecture : public Architecture {
 public:
  /** Pre-decode instruction memory into a macro-op of `A64Instruction`
   * instances. Returns the macro-op generated and the number of bytes consumed
   * to produce it (always 4). */
  std::tuple<MacroOp, uint8_t> predecode(
      const void* ptr, uint8_t bytesAvailable, uint64_t instructionAddress,
      BranchPrediction prediction) const override;

  /** Returns an ARMv8-a register file structure description. */
  std::vector<RegisterFileStructure> getRegisterFileStructure() const override;

  /** Determine whether the specified register can be renamed. */
  bool canRename(Register reg) const override;

 private:
  /** A decoding cache, mapping an instruction word to a previously decoded
   * instruction. Instructions are added to the cache as they're decoded, to
   * reduce the overhead of future decoding. */
  static std::unordered_map<uint32_t, A64Instruction> decodeCache;
};

}  // namespace simeng
