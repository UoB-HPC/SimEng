#include "A64Architecture.hh"

#include <cassert>

#include "A64Instruction.hh"

namespace simeng {

std::unordered_map<uint32_t, A64Instruction> A64Architecture::decodeCache;

std::tuple<MacroOp, uint8_t> A64Architecture::predecode(
    void* ptr, uint8_t bytesAvailable, uint64_t instructionAddress) const {
  assert(bytesAvailable >= 4 && "Fewer than 4 bytes supplied to A64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  uint32_t insn = *static_cast<uint32_t*>(ptr);

  std::shared_ptr<A64Instruction> uop;
  if (decodeCache.count(insn)) {
    // A decoding for this already exists, duplicate and return that
    uop = std::make_shared<A64Instruction>(decodeCache[insn]);
  } else {
    // Generate a fresh decoding, and add to cache
    auto decoded = A64Instruction(insn);
    decodeCache[insn] = decoded;
    uop = std::make_shared<A64Instruction>(decoded);
  }
  uop->setInstructionAddress(instructionAddress);

  // Bundle into a macro-op and return
  return {{uop}, 4};
}

std::vector<std::pair<uint8_t, uint16_t>>
A64Architecture::getRegisterFileStructure() const {
  return {
      {8, 32},   // General purpose
      {16, 32},  // Vector
      {1, 1}     // NZCV
  };
}

bool A64Architecture::canRename(Register reg) const { return true; }

}  // namespace simeng
