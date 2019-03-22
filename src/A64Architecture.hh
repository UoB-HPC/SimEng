#pragma once

#include "Architecture.hh"

#include <unordered_map>

#include "A64Instruction.hh"

using csh = size_t;

namespace simeng {

/* A basic ARMv8-a implementation of the `Architecture` interface. */
class A64Architecture : public Architecture {
 public:
  A64Architecture();
  ~A64Architecture();
  /** Pre-decode instruction memory into a macro-op of `A64Instruction`
   * instances. Returns the number of bytes consumed to produce it (always 4),
   * and writes into the supplied macro-op vector. */
  uint8_t predecode(const void* ptr, uint8_t bytesAvailable,
                    uint64_t instructionAddress, BranchPrediction prediction,
                    MacroOp& output) const override;

  /** Returns an ARMv8-a register file structure description. */
  std::vector<RegisterFileStructure> getRegisterFileStructures() const override;

  /** Determine whether the specified register can be renamed. */
  bool canRename(Register reg) const override;

  void handleException(std::shared_ptr<Instruction> instruction) const override;

 private:
  /** A decoding cache, mapping an instruction word to a previously decoded
   * instruction. Instructions are added to the cache as they're decoded, to
   * reduce the overhead of future decoding. */
  static std::unordered_map<uint32_t, A64Instruction> decodeCache;
  /** A decoding metadata cache, mapping an instruction word to a previously
   * decoded instruction metadata bundle. Metadata is added to the cache as it's
   * decoded, to reduce the overhead of future decoding. */
  static std::unordered_map<uint32_t, A64InstructionMetadata> metadataCache;

  /** A Capstone decoding library handle, for decoding instructions. */
  csh capstoneHandle;
};

}  // namespace simeng
