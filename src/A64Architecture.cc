#include "A64Architecture.hh"

#include <cassert>
#include <iostream>

#include "A64InstructionMetadata.hh"

namespace simeng {

std::unordered_map<uint32_t, A64Instruction> A64Architecture::decodeCache;
std::unordered_map<uint32_t, A64InstructionMetadata>
    A64Architecture::metadataCache;

A64Architecture::A64Architecture() {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "Could not create capstone handle" << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}
A64Architecture::~A64Architecture() { cs_close(&capstoneHandle); }

uint8_t A64Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                   uint64_t instructionAddress,
                                   BranchPrediction prediction,
                                   MacroOp& output) const {
  assert(bytesAvailable >= 4 && "Fewer than 4 bytes supplied to A64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  const uint32_t insn = *static_cast<const uint32_t*>(ptr);
  const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

  if (!decodeCache.count(insn)) {
    // Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    // TODO: capture result (success state) and replace instruction with an
    // "invalid decoding" implementation if not successful
    bool success =
        cs_disasm_iter(capstoneHandle, &encoding, &size, &address, &rawInsn);

    auto metadata = success ? A64InstructionMetadata(rawInsn)
                            : A64InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache.insert({insn, metadata});
    // Create and cache an instruction using the metadata
    decodeCache.insert({insn, metadataCache.find(insn)->second});
  }

  // Retrieve the cached instruction
  std::shared_ptr<Instruction> uop =
      std::make_shared<A64Instruction>(decodeCache.find(insn)->second);

  uop->setInstructionAddress(instructionAddress);
  uop->setBranchPrediction(prediction);

  // Bundle uop into output macro-op and return
  output.resize(1);
  output[0] = uop;

  return 4;
}

void A64Architecture::handleException(
    std::shared_ptr<Instruction> instruction) const {
  A64Instruction* insn = static_cast<A64Instruction*>(instruction.get());

  std::cout << "Encountered ";
  switch (insn->getException()) {
    case A64InstructionException::EncodingUnallocated:
      std::cout << "illegal instruction";
      break;
    case A64InstructionException::ExecutionNotYetImplemented:
      std::cout << "execution not-yet-implemented";
      break;
    default:
      std::cout << "unknown (id: "
                << static_cast<unsigned int>(insn->getException()) << ")";
  }
  std::cout << " exception" << std::endl;
}

std::vector<RegisterFileStructure> A64Architecture::getRegisterFileStructures()
    const {
  return {
      {8, 32},   // General purpose
      {16, 32},  // Vector
      {1, 1}     // NZCV
  };
}

bool A64Architecture::canRename(Register reg) const { return true; }

}  // namespace simeng
