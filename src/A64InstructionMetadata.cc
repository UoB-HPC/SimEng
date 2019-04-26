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

  // Fix some inaccuracies in the decoded metadata
  switch (opcode) {
    case A64Opcode::AArch64_MOVZWi:
      [[fallthrough]];
    case A64Opcode::AArch64_MOVZXi:
      // MOVZ incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case A64Opcode::AArch64_RET:
      // RET doesn't list use of x30 (LR) if no register is supplied
      operandCount = 1;
      operands[0].type = ARM64_OP_REG;
      operands[0].reg = ARM64_REG_LR;
      operands[0].access = CS_AC_READ;
      groupCount = 1;
      groups[0] = CS_GRP_JUMP;
      break;
    case A64Opcode::AArch64_SVC:
      // SVC is incorrectly marked as setting x30
      implicitDestinationCount = 0;
      break;
    case A64Opcode::AArch64_UBFMWri:
      [[fallthrough]];
    case A64Opcode::AArch64_UBFMXri:
      // UBFM incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
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
  switch (opcode) {
    case A64Opcode::AArch64_ADDXri: {
      if (id != ARM64_INS_MOV) return;
      // mov <xd|sp>, <sp|xn>; alias for: add <xd|sp>, <sp|xn>, #0

      operandCount = 3;
      operands[2].type = ARM64_OP_IMM;
      operands[2].imm = 0;
      operands[2].access = CS_AC_READ;
      return;
    }
    case A64Opcode::AArch64_ASRVWr: {
      if (id != ARM64_INS_ASR) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_ASRVXr: {
      if (id != ARM64_INS_ASR) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_BFMWri: {
      if (id == ARM64_INS_BFI) return aliasNYI();
      if (id == ARM64_INS_BFXIL) return aliasNYI();
      return;
    }
    case A64Opcode::AArch64_BFMXri: {
      if (id != ARM64_INS_BFI) return;
      if (id == ARM64_INS_BFXIL) return aliasNYI();
      return aliasNYI();
    }
    case A64Opcode::AArch64_CSINCWr: {
      if (id == ARM64_INS_CSET) {
        // cset wd, cc; alias for: csinc wd, wzr, wzr, invert(cc)
        operandCount = 3;

        operands[1].type = ARM64_OP_REG;
        operands[1].reg = ARM64_REG_WZR;
        operands[1].access = CS_AC_READ;

        operands[2].type = ARM64_OP_REG;
        operands[2].reg = ARM64_REG_WZR;
        operands[2].access = CS_AC_READ;
        cc ^= 1;  // invert lowest bit to negate cc

        return;
      } else if (id == ARM64_INS_CINC) {
        return aliasNYI();
      }
      return;
    }
    case A64Opcode::AArch64_CSINCXr: {
      if (id == ARM64_INS_CSET) {
        // cset xd, cc; alias for: csinc xd, xzr, xzr, invert(cc)

        operandCount = 3;

        operands[1].type = ARM64_OP_REG;
        operands[1].reg = ARM64_REG_XZR;
        operands[1].access = CS_AC_READ;

        operands[2].type = ARM64_OP_REG;
        operands[2].reg = ARM64_REG_XZR;
        operands[2].access = CS_AC_READ;
        cc ^= 1;  // invert lowest bit to negate cc

        return;
      } else if (id == ARM64_INS_CINC) {
        return aliasNYI();
      }
    }
    case A64Opcode::AArch64_CSINVWr: {
      if (id != ARM64_INS_CINV) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_CSINVXr: {
      if (id != ARM64_INS_CINV) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_ORRWrs: {
      if (id != ARM64_INS_MOV) return;
      // mov wd, wn; alias for orr wd, wzr, wn
      operandCount = 3;
      operands[2] = operands[1];

      operands[1].type = ARM64_OP_REG;
      operands[1].reg = ARM64_REG_WZR;
      operands[1].access = CS_AC_READ;
      operands[1].shift = {ARM64_SFT_INVALID, 0};
      return;
    }
    case A64Opcode::AArch64_ORRXrs: {
      if (id != ARM64_INS_MOV) return;
      // mov xd, xn; alias for orr xd, xzr, xn
      operandCount = 3;
      operands[2] = operands[1];

      operands[1].type = ARM64_OP_REG;
      operands[1].reg = ARM64_REG_XZR;
      operands[1].access = CS_AC_READ;
      operands[1].shift = {ARM64_SFT_INVALID, 0};
      return;
    }
    case A64Opcode::AArch64_SBFMWri: {
      if (id != ARM64_INS_ASR) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_SBFMXri: {
      if (id != ARM64_INS_ASR) return;
      return aliasNYI();
    }
    case A64Opcode::AArch64_SUBSWri: {
      if (id != ARM64_INS_CMP) return;
      // cmp wn, #imm; alias for: subs wzr, wn, #imm
      operandCount = 3;
      operands[2] = operands[1];

      operands[1] = operands[0];
      operands[1].access = CS_AC_READ;

      operands[0].type = ARM64_OP_REG;
      operands[0].reg = ARM64_REG_WZR;
      operands[0].access = CS_AC_WRITE;
      return;
    }
    case A64Opcode::AArch64_SUBSWrs: {
      if (id != ARM64_INS_CMP) return;
      // cmp wn, wm; alias for: subs xzr, xn, xm
      operandCount = 3;
      operands[2] = operands[1];

      operands[1] = operands[0];
      operands[1].access = CS_AC_READ;

      operands[0].type = ARM64_OP_REG;
      operands[0].reg = ARM64_REG_XZR;
      operands[0].access = CS_AC_WRITE;
      return;
    }
    case A64Opcode::AArch64_SUBSXri: {
      if (id != ARM64_INS_CMP) return;
      // cmp xn, #imm; alias for: subs xzr, xn, #imm
      operandCount = 3;
      operands[2] = operands[1];

      operands[1] = operands[0];
      operands[1].access = CS_AC_READ;

      operands[0].type = ARM64_OP_REG;
      operands[0].reg = ARM64_REG_XZR;
      operands[0].access = CS_AC_WRITE;
      return;
    }
    case A64Opcode::AArch64_SYSxt: {
      if (id == ARM64_INS_AT) return aliasNYI();
      return;
    }

    case A64Opcode::AArch64_UBFMWri: {
      if (id == ARM64_INS_LSL) {
        // lsl wd, wn, #shift; alias for:
        //  ubfm wd, wn, #(-shift MOD 32), #(31 - shift)
        operandCount = 4;

        auto shift = operands[2].imm;
        operands[2].imm = (-shift) & 31;
        operands[3].type = ARM64_OP_IMM;
        operands[3].imm = 31 - shift;
        operands[3].access = CS_AC_READ;
        return;
      } else if (id == ARM64_INS_LSR) {
        return aliasNYI();
      }
      return;
    }
    case A64Opcode::AArch64_UBFMXri: {
      if (id == ARM64_INS_LSL) {
        // lsl xd, xn, #shift; alias for:
        //  ubfm xd, xn, #(-shift MOD 64), #(64 - shift)
        operandCount = 4;

        auto shift = operands[2].imm;
        operands[2].imm = (-shift) & 63;
        operands[3].type = ARM64_OP_IMM;
        operands[3].imm = 63 - shift;
        operands[3].access = CS_AC_READ;
        return;
      } else if (id == ARM64_INS_LSR) {
        return aliasNYI();
      }
      return;
    }
  }
}

void A64InstructionMetadata::aliasNYI() { id = ARM64_INS_INVALID; }

}  // namespace simeng
