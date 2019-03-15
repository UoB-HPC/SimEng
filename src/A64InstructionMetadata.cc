#include "A64InstructionMetadata.hh"

namespace simeng {

A64InstructionMetadata::A64InstructionMetadata(const cs_insn& insn)
    : id(insn.id),
      opcode(insn.opcode),
      implicitSourceCount(insn.detail->regs_read_count),
      implicitDestinationCount(insn.detail->regs_write_count),
      groupCount(insn.detail->groups_count),
      cc(insn.detail->arm64.cc - 1),
      setsFlags(insn.detail->arm64.update_flags),
      writeback(insn.detail->arm64.writeback),
      operandCount(insn.detail->arm64.op_count) {
  // Copy printed output
  std::strncpy(mnemonic, insn.mnemonic, CS_MNEMONIC_SIZE);
  std::strncpy(operandStr, insn.op_str, sizeof(operandStr));

  // Copy register/group/operand information
  std::memcpy(implicitSources, insn.detail->regs_read,
              sizeof(uint16_t) * implicitSourceCount);
  std::memcpy(implicitDestinations, insn.detail->regs_write,
              sizeof(uint16_t) * implicitDestinationCount);
  std::memcpy(groups, insn.detail->groups, sizeof(uint8_t) * groupCount);
  std::memcpy(operands, insn.detail->arm64.operands,
              sizeof(cs_arm64_op) * operandCount);

  if (id == ARM64_INS_ORR) {
    // Manual patch for bad ORR access specifier
    // Destination register is incorrectly listed as read|write instead of write
    operands[0].access = CS_AC_WRITE;
  } else if (id == ARM64_INS_LDR) {
    // Manual patch for bad LDR access specifier
    // Destination register is incorrectly listed as read|write instead of write
    operands[0].access = CS_AC_WRITE;
  } else if (id == ARM64_INS_STR) {
    // Manual patch for bad STR access specifier
    // Destination register is incorrectly listed as read|write instead of read
    operands[0].access = CS_AC_READ;
  }
}

}  // namespace simeng
