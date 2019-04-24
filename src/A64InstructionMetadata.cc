#include "A64InstructionMetadata.hh"

#include <cstring>

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
  std::memcpy(encoding, insn.bytes, sizeof(encoding));
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

  if (opcode == A64Opcode::AArch64_MOVZWi ||
      opcode == A64Opcode::AArch64_MOVZXi) {
    // MOVZ incorrectly flags destination as READ | WRITE
    operands[0].access = CS_AC_WRITE;
  } else if (opcode == A64Opcode::AArch64_RET) {
    // RET doesn't list use of x30 (LR) if no register is supplied
    operandCount = 1;
    operands[0].type = ARM64_OP_REG;
    operands[0].reg = ARM64_REG_LR;
    operands[0].access = CS_AC_READ;
    groupCount = 1;
    groups[0] = CS_GRP_JUMP;
  } else if (opcode == A64Opcode::AArch64_SVC) {
    // SVC is incorrectly marked as setting x30
    implicitDestinationCount = 0;
  }

  revertAliasing();
}

A64InstructionMetadata::A64InstructionMetadata(const uint8_t* invalidEncoding)
    : id(ARM64_INS_INVALID),
      opcode(A64Opcode::AArch64_INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      groupCount(0),
      setsFlags(false),
      writeback(false),
      operandCount(0) {
  std::memcpy(encoding, invalidEncoding, sizeof(encoding));
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

void A64InstructionMetadata::revertAliasing() {
  if (opcode == A64Opcode::AArch64_CSINCWr &&
      !std::strncmp(mnemonic, "cset", 4)) {
    // cset wd, cc; alias for: csinc wd, wzr, wzr, invert(cc)
    operandCount = 3;

    operands[1].type = ARM64_OP_REG;
    operands[1].reg = ARM64_REG_WZR;
    operands[1].access = CS_AC_READ;

    operands[2].type = ARM64_OP_REG;
    operands[2].reg = ARM64_REG_WZR;
    operands[2].access = CS_AC_READ;
    cc ^= 1;  // invert lowest bit to negate cc
  } else if (opcode == A64Opcode::AArch64_CSINCXr &&
             !std::strncmp(mnemonic, "cset", 4)) {
    // cset xd, cc; alias for: csinc xd, xzr, xzr, invert(cc)
    operandCount = 3;

    operands[1].type = ARM64_OP_REG;
    operands[1].reg = ARM64_REG_XZR;
    operands[1].access = CS_AC_READ;

    operands[2].type = ARM64_OP_REG;
    operands[2].reg = ARM64_REG_XZR;
    operands[2].access = CS_AC_READ;
    cc ^= 1;  // invert lowest bit to negate cc
  } else if (opcode == A64Opcode::AArch64_ORRXrs &&
             !std::strncmp(mnemonic, "mov", 3)) {
    operandCount = 3;
    operands[2] = operands[1];

    operands[1].type = ARM64_OP_REG;
    operands[1].reg = ARM64_REG_XZR;
    operands[1].access = CS_AC_READ;
    operands[1].shift = {ARM64_SFT_INVALID, 0};
  } else if (opcode == A64Opcode::AArch64_SUBSWri &&
             !std::strncmp(mnemonic, "cmp", 3)) {
    // cmp wn, #imm; alias for: subs wzr, wn, #imm
    operandCount = 3;
    operands[2] = operands[1];

    operands[1] = operands[0];
    operands[1].access = CS_AC_READ;

    operands[0].type = ARM64_OP_REG;
    operands[0].reg = ARM64_REG_WZR;
    operands[0].access = CS_AC_WRITE;
  } else if (opcode == A64Opcode::AArch64_SUBSXri &&
             !std::strncmp(mnemonic, "cmp", 3)) {
    // cmp xn, #imm; alias for: subs xzr, xn, #imm
    operandCount = 3;
    operands[2] = operands[1];

    operands[1] = operands[0];
    operands[1].access = CS_AC_READ;

    operands[0].type = ARM64_OP_REG;
    operands[0].reg = ARM64_REG_XZR;
    operands[0].access = CS_AC_WRITE;
  }
}

}  // namespace simeng
