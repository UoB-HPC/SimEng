#include "A64Architecture.hh"

#include <cassert>

namespace simeng {

std::unordered_map<uint32_t, A64Instruction> A64Architecture::decodeCache;

uint8_t A64Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                   uint64_t instructionAddress,
                                   BranchPrediction prediction,
                                   MacroOp& output) const {
  assert(bytesAvailable >= 4 && "Fewer than 4 bytes supplied to A64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  const uint32_t insn = *static_cast<const uint32_t*>(ptr);

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
  uop->setBranchPrediction(prediction);

  // Bundle uop into output macro-op and return
  output.resize(1);
  output[0] = uop;

  return 4;
}

std::vector<RegisterFileStructure> A64Architecture::getRegisterFileStructure()
    const {
  return {
      {8, 32},   // General purpose
      {16, 32},  // Vector
      {1, 1}     // NZCV
  };
}

bool A64Architecture::canRename(Register reg) const { return true; }

}  // namespace simeng
