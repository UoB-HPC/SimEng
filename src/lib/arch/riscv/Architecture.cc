#include "simeng/arch/riscv/Architecture.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace riscv {

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;

Architecture::Architecture(kernel::Linux& kernel, YAML::Node config) : linux_(kernel) {
  cs_err n = cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &capstoneHandle);
  if (n != CS_ERR_OK) {
    std::cerr << "Could not create capstone handle due to error " << n << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
//  systemRegisterMap_[ARM64_SYSREG_DCZID_EL0] = systemRegisterMap_.size();
//  systemRegisterMap_[ARM64_SYSREG_FPCR] = systemRegisterMap_.size();
//  systemRegisterMap_[ARM64_SYSREG_FPSR] = systemRegisterMap_.size();
//  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL0] = systemRegisterMap_.size();
//  systemRegisterMap_[ARM64_SYSREG_MIDR_EL1] = systemRegisterMap_.size();
//  systemRegisterMap_[ARM64_SYSREG_CNTVCT_EL0] = systemRegisterMap_.size();
}
Architecture::~Architecture() { cs_close(&capstoneHandle); }

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                BranchPrediction prediction,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv8
  // TODO Check this is a requirement in RISCV
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    uop->setBranchPrediction(prediction);
    // Return non-zero value to avoid fatal error
    return 1;
  }

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
        {insn,
         {*this, metadataCache.front(), latencies.first, latencies.second}});

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
  uint16_t numSysRegs = static_cast<uint16_t>(systemRegisterMap_.size());
  return {
      {8, 32},          // General purpose
      {8, 32},          // Floating Point
//      {256, 32},        // Vector
//      {32, 17},         // Predicate
//      {1, 1},           // NZCV
      {8, numSysRegs},  // System
  };
}

uint16_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  assert(systemRegisterMap_.count(reg) && "unhandled system register");
  return systemRegisterMap_.at(reg);
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type
  changes.type = ChangeType::REPLACEMENT;

  uint64_t stackPointer = linux_.getInitialStackPointer();
  // Set the stack pointer register
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 2});
  changes.modifiedRegisterValues.push_back(stackPointer);

  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  // changes.modifiedRegisters.push_back(
  //     {RegisterType::SYSTEM, getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)});
  // changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(0b10100));

  return changes;
}

ProcessStateChange Architecture::getUpdateState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type~constructor
  changes.type = ChangeType::INCREMENT;

  // Increment the Counter-timer Virtual Count (CNTVCT) register by 1
  /* TODO: CNTVCT value should be equal to the physical count value minus the
   * virtual offset visible in CNTVOFF. */
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM, getSystemRegisterTag(ARM64_SYSREG_CNTVCT_EL0)});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(1));

  return changes;
}

std::pair<uint8_t, uint8_t> Architecture::getLatencies(
    InstructionMetadata& metadata) const {
  const std::pair<uint8_t, uint8_t> FPSIMD_LATENCY = {6, 1};

  // Look up the instruction opcode to get the latency
  switch (metadata.opcode) {

  }

  // Assume single-cycle, non-blocking for all other instructions
  return {1, 1};
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
