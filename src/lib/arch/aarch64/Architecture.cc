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

  // Generate zero-indexed system register map
  systemRegisterMap_[ARM64_SYSREG_DCZID_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[0xda20] = systemRegisterMap_.size();  // FPCR
  systemRegisterMap_[0xda21] = systemRegisterMap_.size();
  systemRegisterMap_[0xde82] = systemRegisterMap_.size();  // TPIDR_EL0
  systemRegisterMap_[0xc000] = systemRegisterMap_.size();  // MIDR_EL1
  systemRegisterMap_[0xdf14] = systemRegisterMap_.size();
}
Architecture::~Architecture() { cs_close(&capstoneHandle); }

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                BranchPrediction prediction,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv8
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
      {16, 32},         // Vector
      {1, 1},           // NZCV
      {8, numSysRegs},  // System
  };
}

uint16_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  assert(systemRegisterMap_.count(reg) && "unhandled system register");
  return systemRegisterMap_.at(reg);
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;

  uint64_t stackPointer = linux_.getInitialStackPointer();
  // Set the stack pointer register
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 31});
  changes.modifiedRegisterValues.push_back(stackPointer);

  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM, getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(0b10100));

  return changes;
}

std::pair<uint8_t, uint8_t> Architecture::getLatencies(
    InstructionMetadata& metadata) const {
  const std::pair<uint8_t, uint8_t> FPSIMD_LATENCY = {6, 1};

  // Look up the instruction opcode to get the latency
  switch (metadata.opcode) {
    case Opcode::AArch64_FDIVDrr:
    case Opcode::AArch64_FDIVv2f64:
    case Opcode::AArch64_FSQRTDr:
      return {43,43};
    case Opcode::AArch64_FDIVSrr:
    case Opcode::AArch64_FSQRTSr:
    case Opcode::AArch64_FSQRTv4f32:
      return {29,29};
    case Opcode::AArch64_SDIVWr:
    case Opcode::AArch64_SDIVXr:
      return {42,42};
    case Opcode::AArch64_UDIVWr:
    case Opcode::AArch64_UDIVXr:
      return {41,41};
    case Opcode::AArch64_FADDDrr:
    case Opcode::AArch64_FADDSrr:
    case Opcode::AArch64_FADDv2f64:
    case Opcode::AArch64_FADDv4f32:
    case Opcode::AArch64_FADDPv2i64p:
    case Opcode::AArch64_FMADDDrrr:
    case Opcode::AArch64_FMADDSrrr:
    case Opcode::AArch64_FMULDrr:
    case Opcode::AArch64_FMULSrr:
    case Opcode::AArch64_FMULv1i32_indexed:
    case Opcode::AArch64_FMULv1i64_indexed:
    case Opcode::AArch64_FMULv2f64:
    case Opcode::AArch64_FMULv4f32:
    case Opcode::AArch64_FMULv4i32_indexed:
    case Opcode::AArch64_FMLAv2f64:
    case Opcode::AArch64_FMLAv4f32:
    case Opcode::AArch64_FMLAv4i32_indexed:
    case Opcode::AArch64_FMLSv4f32:
    case Opcode::AArch64_FMLSv4i32_indexed:
    case Opcode::AArch64_FNMSUBDrrr:
    case Opcode::AArch64_FNMSUBSrrr:
    case Opcode::AArch64_FSUBDrr:
    case Opcode::AArch64_FSUBSrr:
    case Opcode::AArch64_FSUBv2f64:
    case Opcode::AArch64_FSUBv4f32:
      return {9, 1};
    case Opcode::AArch64_CPYi32:
    case Opcode::AArch64_CPYi64:
    case Opcode::AArch64_DUPv16i8gpr:
    case Opcode::AArch64_DUPv2i32gpr:
    case Opcode::AArch64_DUPv2i32lane:
    case Opcode::AArch64_DUPv2i64gpr:
    case Opcode::AArch64_DUPv2i64lane:
    case Opcode::AArch64_DUPv4i16gpr:
    case Opcode::AArch64_DUPv4i32gpr:
    case Opcode::AArch64_DUPv4i32lane:
    case Opcode::AArch64_FMOVDXHighr:
    case Opcode::AArch64_FMOVWSr:
    case Opcode::AArch64_FMOVXDHighr:
    case Opcode::AArch64_FMOVXDr:
    case Opcode::AArch64_SSHLLv2i32_shift:
    case Opcode::AArch64_USHLLv4i16_shift:
    case Opcode::AArch64_UMOVvi32:
    case Opcode::AArch64_UMOVvi64:
    case Opcode::AArch64_XTNv2i32:
    case Opcode::AArch64_XTNv4i16:
    case Opcode::AArch64_XTNv4i32:
      return {6, 1};
    case Opcode::AArch64_ADDPv16i8:
    case Opcode::AArch64_ADDPv2i64:
    case Opcode::AArch64_ADDPv4i32:
    case Opcode::AArch64_ADDPv8i16:
    case Opcode::AArch64_ANDv16i8:
    case Opcode::AArch64_ANDv8i8:
    case Opcode::AArch64_BSLv16i8:
    case Opcode::AArch64_BICWrs:
    case Opcode::AArch64_BICXrs:
    case Opcode::AArch64_BICSXrs:
    case Opcode::AArch64_BIFv16i8:
    case Opcode::AArch64_BITv16i8:
    case Opcode::AArch64_FABSDr:
    case Opcode::AArch64_FABSSr:
    case Opcode::AArch64_FABSv2f64:
    case Opcode::AArch64_FABSv4f32:
    case Opcode::AArch64_FCCMPDrr:
    case Opcode::AArch64_FCCMPEDrr:
    case Opcode::AArch64_FCCMPSrr:
    case Opcode::AArch64_FCCMPESrr:
    case Opcode::AArch64_FCMGEv2i64rz:
    case Opcode::AArch64_FCMGEv4i32rz:
    case Opcode::AArch64_FCMGTv4f32:
    case Opcode::AArch64_FCMLTv4i32rz:
    case Opcode::AArch64_FCMPDri:
    case Opcode::AArch64_FCMPEDri:
    case Opcode::AArch64_FCMPDrr:
    case Opcode::AArch64_FCMPEDrr:
    case Opcode::AArch64_FCMPSri:
    case Opcode::AArch64_FCMPESri:
    case Opcode::AArch64_FCMPSrr:
    case Opcode::AArch64_FCMPESrr:
    case Opcode::AArch64_FCSELDrrr:
    case Opcode::AArch64_FCSELSrrr:
    case Opcode::AArch64_FMAXNMDrr:
    case Opcode::AArch64_FMAXNMv2f64:
    case Opcode::AArch64_FMAXNMPv2i64p:
    case Opcode::AArch64_FMINNMDrr:
    case Opcode::AArch64_FMINNMv2f64:
    case Opcode::AArch64_FMINNMPv2i64p:
    case Opcode::AArch64_FMOVDi:
    case Opcode::AArch64_FMOVDr:
    case Opcode::AArch64_FMOVSi:
    case Opcode::AArch64_FMOVSr:
    case Opcode::AArch64_FMOVv2f64_ns:
    case Opcode::AArch64_FMOVv4f32_ns:
    case Opcode::AArch64_FNEGDr:
    case Opcode::AArch64_FNEGSr:
    case Opcode::AArch64_FNEGv2f64:
    case Opcode::AArch64_FNEGv4f32:
    case Opcode::AArch64_MOVID:
    case Opcode::AArch64_MOVIv2d_ns:
    case Opcode::AArch64_MOVIv2i32:
    case Opcode::AArch64_MOVIv4i32:
    case Opcode::AArch64_ORRv16i8:
    case Opcode::AArch64_SHLv4i32_shift:
    case Opcode::AArch64_SMAXv4i32:
    case Opcode::AArch64_SMINVv4i32v:
    case Opcode::AArch64_SMINv4i32:
    case Opcode::AArch64_SSHRv4i32_shift:
      return {4, 1};
    case Opcode::AArch64_ANDSWrs:
    case Opcode::AArch64_ANDSXrs:
    case Opcode::AArch64_ANDWrs:
    case Opcode::AArch64_ANDXrs:
    case Opcode::AArch64_ORNWrs:
    case Opcode::AArch64_ORNXrs:
    case Opcode::AArch64_ORRWrs:
    case Opcode::AArch64_ORRXrs:
      if (metadata.operands[2].shift.value > 0) {
        return {2, 2};
      }
      return {1, 1};
    case Opcode::AArch64_ADDSWrs:
    case Opcode::AArch64_ADDSXrs:
    case Opcode::AArch64_ADDWrs:
    case Opcode::AArch64_ADDXrs:
    case Opcode::AArch64_SUBSWrs:
    case Opcode::AArch64_SUBSXrs:
      if (metadata.operands[2].shift.value > 4) {
        return {3, 3};
      }
      if (metadata.operands[2].shift.value > 0 && metadata.operands[2].shift.type == 1) {
        return {2, 2};
      }
      return {1, 1};
    case Opcode::AArch64_LD1Rv4s_POST:
    case Opcode::AArch64_LD1Twov16b:
    case Opcode::AArch64_LDPDi:
    case Opcode::AArch64_LDPQi:
    case Opcode::AArch64_LDPSi:
    case Opcode::AArch64_LDPWi:
    case Opcode::AArch64_LDPXi:
    case Opcode::AArch64_LDRBBpost:
    case Opcode::AArch64_LDRBBpre:
    case Opcode::AArch64_LDRDpost:
    case Opcode::AArch64_LDRDpre:
    case Opcode::AArch64_LDRHHpost:
    case Opcode::AArch64_LDRHHpre:
    case Opcode::AArch64_LDRSpost:
    case Opcode::AArch64_LDRSpre: 
    case Opcode::AArch64_LDRWpost:
    case Opcode::AArch64_LDRWpre:
    case Opcode::AArch64_LDRXpost:
    case Opcode::AArch64_LDRXpre:
      return {2,2};
    case Opcode::AArch64_LD1Twov16b_POST:
    case Opcode::AArch64_LDPDpost:
    case Opcode::AArch64_LDPDpre:
    case Opcode::AArch64_LDPQpost:
    case Opcode::AArch64_LDPQpre:
    case Opcode::AArch64_LDPXpost:
    case Opcode::AArch64_LDPXpre:
      return {3,3};
    // Non-indexed stores
    case Opcode::AArch64_STRBBroW:
    case Opcode::AArch64_STRBBroX:
    case Opcode::AArch64_STRBBui:
    case Opcode::AArch64_STRHHui:
    case Opcode::AArch64_STRWroW:
    case Opcode::AArch64_STRWroX:
    case Opcode::AArch64_STRWui:
    case Opcode::AArch64_STRXroW:
    case Opcode::AArch64_STRXroX:
    case Opcode::AArch64_STRXui:
    case Opcode::AArch64_STURBBi:
    case Opcode::AArch64_STURWi:
    case Opcode::AArch64_STURXi:
      return {5,1};
    case Opcode::AArch64_STRDroW:
    case Opcode::AArch64_STRDroX:
    case Opcode::AArch64_STRDui:
    case Opcode::AArch64_STRHHroW:
    case Opcode::AArch64_STRHHroX:
    case Opcode::AArch64_STRQroX:
    case Opcode::AArch64_STRQui:
    case Opcode::AArch64_STRSroW:
    case Opcode::AArch64_STRSroX:
    case Opcode::AArch64_STRSui:
    case Opcode::AArch64_STURDi:
    case Opcode::AArch64_STURQi: 
    case Opcode::AArch64_STURSi:
      return {8,1};
    // STR indexed
    case Opcode::AArch64_STRBBpost:
    case Opcode::AArch64_STRBBpre:
    case Opcode::AArch64_STRWpost:
    case Opcode::AArch64_STRWpre:
    case Opcode::AArch64_STRXpost:
    case Opcode::AArch64_STRXpre:
      return {5,2};
    case Opcode::AArch64_STLXRW:
    case Opcode::AArch64_STLXRX:
    case Opcode::AArch64_STRDpost:
    case Opcode::AArch64_STRDpre:
    case Opcode::AArch64_STRHHpost:
    case Opcode::AArch64_STRHHpre:
    case Opcode::AArch64_STRQpost:
    case Opcode::AArch64_STRSpost:
    case Opcode::AArch64_STRSpre:
    case Opcode::AArch64_STXRW:
      return {8,2};
    // STP
    case Opcode::AArch64_STPXi:
    case Opcode::AArch64_STPWi:
      return {6,2};
    case Opcode::AArch64_STPDi:
    case Opcode::AArch64_STPSi:
    case Opcode::AArch64_STPQi:
      return {9,2};
    case Opcode::AArch64_STPXpre:
      return {6,3};
    case Opcode::AArch64_STPDpost:
    case Opcode::AArch64_STPDpre:
    case Opcode::AArch64_STPSpost:
    case Opcode::AArch64_STPSpre:
    case Opcode::AArch64_STPQpost:
      return {9,3};
  }

  // Assume single-cycle, non-blocking for all other instructions
  return {1, 1};
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
