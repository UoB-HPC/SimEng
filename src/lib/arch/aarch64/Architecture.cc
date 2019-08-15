#include "simeng/arch/aarch64/Architecture.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;

Architecture::Architecture(kernel::Linux& kernel) : linux_(kernel) {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "Could not create capstone handle" << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
}
Architecture::~Architecture() { cs_close(&capstoneHandle); }

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                BranchPrediction prediction,
                                MacroOp& output) const {
  assert(bytesAvailable >= 4 &&
         "Fewer than 4 bytes supplied to AArch64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  const uint32_t insn = *static_cast<const uint32_t*>(ptr);
  const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

  // Try to find the decoding in the decode cache
  auto iter = decodeCache.find(insn);
  if (iter == decodeCache.end()) {
    // No decoding present. Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    bool success =
        cs_disasm_iter(capstoneHandle, &encoding, &size, &address, &rawInsn);

    auto metadata =
        success ? InstructionMetadata(rawInsn) : InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache.emplace_front(metadata);

    // Get the latencies for this instruction
    auto latencies = getLatencies(metadata);

    // Create and cache an instruction using the metadata and latencies
    auto result = decodeCache.insert(
        {insn, {metadataCache.front(), latencies.first, latencies.second}});

    iter = result.first;
  }

  output.resize(1);
  auto& uop = output[0];

  // Retrieve the cached instruction and write to output
  uop = std::make_shared<Instruction>(iter->second);

  uop->setInstructionAddress(instructionAddress);
  uop->setBranchPrediction(prediction);

  return 4;
}

std::shared_ptr<arch::ExceptionHandler> Architecture::handleException(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory) const {
  return std::make_shared<ExceptionHandler>(instruction, core, memory, linux_);
}

std::vector<RegisterFileStructure> Architecture::getRegisterFileStructures()
    const {
  return {
      {8, 32},   // General purpose
      {16, 32},  // Vector
      {1, 1}     // NZCV
  };
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;

  uint64_t stackPointer = linux_.getInitialStackPointer();
  // Set the stack pointer register
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 31});
  changes.modifiedRegisterValues.push_back(stackPointer);

  return changes;
}

bool Architecture::canRename(Register reg) const { return true; }

std::pair<uint8_t, uint8_t> Architecture::getLatencies(
    InstructionMetadata& metadata) const {
  const std::pair<uint8_t, uint8_t> FPSIMD_LATENCY = {6, 1};

  // Look up the instruction opcode to get the latency
  switch (metadata.opcode) {
    case Opcode::AArch64_FADDv2f64:
      return FPSIMD_LATENCY;
    case Opcode::AArch64_FMULv2f64:
      return FPSIMD_LATENCY;
    case Opcode::AArch64_FMLAv2f64:
      return FPSIMD_LATENCY;
  }

  // Assume single-cycle, non-blocking for all other instructions
  return {1, 1};
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
