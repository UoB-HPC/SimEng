#include "InstructionMetadata.hh"

#include <cstring>

namespace simeng {
namespace arch {
namespace aarch64 {

InstructionMetadata::InstructionMetadata(const cs_insn& insn)
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
    case Opcode::AArch64_MOVZWi:
      [[fallthrough]];
    case Opcode::AArch64_MOVZXi:
      // MOVZ incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_MRS:
      // MRS incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_MSR:
      // MSR incorrectly flags source/destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_RET:
      // RET doesn't list use of x30 (LR) if no register is supplied
      operandCount = 1;
      operands[0].type = ARM64_OP_REG;
      operands[0].reg = ARM64_REG_LR;
      operands[0].access = CS_AC_READ;
      groupCount = 1;
      groups[0] = CS_GRP_JUMP;
      break;
    case Opcode::AArch64_SBFMWri:
      [[fallthrough]];
    case Opcode::AArch64_SBFMXri:
      // SBFM incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_SVC:
      // SVC is incorrectly marked as setting x30
      implicitDestinationCount = 0;
      break;
    case Opcode::AArch64_UBFMWri:
      [[fallthrough]];
    case Opcode::AArch64_UBFMXri:
      // UBFM incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
  }

  revertAliasing();
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding)
    : id(ARM64_INS_INVALID),
      opcode(Opcode::AArch64_INSTRUCTION_LIST_END),
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

void InstructionMetadata::revertAliasing() {
  // Check mnemonics known to be aliases and see if their opcode matches
  // something else
  switch (id) {
    case ARM64_INS_ASR:
      if (opcode == Opcode::AArch64_SBFMWri ||
          opcode == Opcode::AArch64_SBFMXri) {
        operandCount = 4;

        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;
        if (opcode == Opcode::AArch64_SBFMWri) {
          // 32-bit
          operands[3].imm = 31;
        } else {
          operands[3].imm = 63;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_AT:
      return aliasNYI();
    case ARM64_INS_BFI:
      return aliasNYI();
    case ARM64_INS_BFXIL:
      return aliasNYI();
    case ARM64_INS_CINC:
      return aliasNYI();
    case ARM64_INS_CINV:
      return aliasNYI();
    case ARM64_INS_CMN:
      // cmn <operands>, alias for adds <wzr|xzr> <operands>
      operandCount = 3;
      operands[2] = operands[1];
      operands[1] = operands[0];
      operands[1].access = CS_AC_READ;

      operands[0].type = ARM64_OP_REG;
      operands[0].access = CS_AC_WRITE;

      if (opcode == Opcode::AArch64_ADDSXri ||
          opcode == Opcode::AArch64_ADDSXrr ||
          opcode == Opcode::AArch64_ADDSXrs) {
        // 64-bit version
        operands[0].reg = ARM64_REG_XZR;
      } else {
        // 32-bit version
        operands[0].reg = ARM64_REG_WZR;
      }
      return;
    case ARM64_INS_CMP:
      if (opcode == Opcode::AArch64_SUBSWri ||
          opcode == Opcode::AArch64_SUBSWrs ||
          opcode == Opcode::AArch64_SUBSXri ||
          opcode == Opcode::AArch64_SUBSXrs) {
        operandCount = 3;
        operands[2] = operands[1];

        operands[1] = operands[0];
        operands[1].access = CS_AC_READ;

        operands[0].type = ARM64_OP_REG;
        operands[0].access = CS_AC_WRITE;

        if (opcode == Opcode::AArch64_SUBSWri ||
            opcode == Opcode::AArch64_SUBSWrs) {
          operands[0].reg = ARM64_REG_WZR;
        } else {
          operands[0].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_CNEG:
      return aliasNYI();
    case ARM64_INS_CSET:
      if (opcode == Opcode::AArch64_CSINCWr ||
          opcode == Opcode::AArch64_CSINCXr) {
        // cset rd, cc; alias for: csinc rd, zr, zr, invert(cc)
        operandCount = 3;

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;

        operands[2].type = ARM64_OP_REG;
        operands[2].access = CS_AC_READ;

        if (opcode == Opcode::AArch64_CSINCWr) {
          operands[1].reg = ARM64_REG_WZR;
          operands[2].reg = ARM64_REG_WZR;
        } else {
          operands[1].reg = ARM64_REG_XZR;
          operands[2].reg = ARM64_REG_XZR;
        }

        cc ^= 1;  // invert lowest bit to negate cc

        return;
      }
      return aliasNYI();
    case ARM64_INS_CSETM:
      return aliasNYI();
    case ARM64_INS_DC:
      return aliasNYI();
    case ARM64_INS_IC:
      return aliasNYI();
    case ARM64_INS_LSL:
      if (opcode == Opcode::AArch64_UBFMWri ||
          opcode == Opcode::AArch64_UBFMXri) {
        // lsl rd, rn, #shift; alias for:
        //  ubfm rd, rn, #(-shift MOD <32|64>), #(<31|63> - shift)
        operandCount = 4;
        uint8_t highestBit = 63;
        if (opcode == Opcode::AArch64_UBFMWri) {
          highestBit = 31;
        }

        auto shift = operands[2].imm;
        operands[2].imm = (-shift) & highestBit;
        operands[3].type = ARM64_OP_IMM;
        operands[3].imm = highestBit - shift;
        operands[3].access = CS_AC_READ;
        return;
      }
      if (opcode == Opcode::AArch64_LSLVWr ||
          opcode == Opcode::AArch64_LSLVXr) {
        return;
      }
      return aliasNYI();
    case ARM64_INS_LSR:
      if (opcode == Opcode::AArch64_UBFMWri ||
          opcode == Opcode::AArch64_UBFMXri) {
        // lsr rd, rn, #amount; alias for ubfm rd, rn, #amount, #<31|63>
        operandCount = 4;

        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;

        if (opcode == Opcode::AArch64_UBFMWri) {
          operands[3].imm = 31;
        } else {
          operands[3].imm = 63;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_MNEG:
      return aliasNYI();
    case ARM64_INS_MOV:
      if (opcode == Opcode::AArch64_ADDXri ||
          opcode == Opcode::AArch64_ADDWri) {
        // mov to/from sp; alias for: add <sp|rd>, <rn|sp>, #0
        operandCount = 3;
        operands[2].type = ARM64_OP_IMM;
        operands[2].imm = 0;
        operands[2].access = CS_AC_READ;
        return;
      }
      if (opcode == Opcode::AArch64_ORRWrs ||
          opcode == Opcode::AArch64_ORRXrs) {
        // mov rd, rn; alias for: orr rd, zr, rn
        operandCount = 3;
        operands[2] = operands[1];

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        if (opcode == Opcode::AArch64_ORRWrs) {
          operands[1].reg = ARM64_REG_WZR;
        } else {
          operands[1].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_MUL:
      if (opcode == Opcode::AArch64_MADDXrrr ||
          opcode == Opcode::AArch64_MADDWrrr) {
        operandCount = 4;
        operands[3].type = ARM64_OP_REG;
        operands[3].access = CS_AC_READ;
        if (opcode == Opcode::AArch64_MADDWrrr) {
          operands[3].reg = ARM64_REG_WZR;
        } else {
          operands[3].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_MVN:
      return aliasNYI();
    case ARM64_INS_NEG:
      if (opcode == Opcode::AArch64_SUBWrs ||
          opcode == Opcode::AArch64_SUBXrs) {
        // neg rd, rm{, shift #amount}; alias for:
        //  sub rd, zr, rm{, shift #amount}
        operandCount = 3;
        operands[2] = operands[1];

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;

        if (opcode == Opcode::AArch64_SUBWrs) {
          operands[1].reg = ARM64_REG_WZR;
        } else {
          operands[1].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_NEGS:
      return aliasNYI();
    case ARM64_INS_NGC:
      return aliasNYI();
    case ARM64_INS_NGCS:
      return aliasNYI();
    case ARM64_INS_REV64:
      return aliasNYI();
    case ARM64_INS_ROR:
      return aliasNYI();
    case ARM64_INS_SBFIZ:
      return aliasNYI();
    case ARM64_INS_SBFX:
      return aliasNYI();
    case ARM64_INS_SMNEGL:
      return aliasNYI();
    case ARM64_INS_SMULL:
      return aliasNYI();
    case ARM64_INS_SXTB:
      return aliasNYI();
    case ARM64_INS_SXTH:
      return aliasNYI();
    case ARM64_INS_SXTW:
      if (opcode == Opcode::AArch64_SBFMXri) {
        operandCount = 4;

        operands[2].type = ARM64_OP_IMM;
        operands[2].access = CS_AC_READ;
        operands[2].imm = 0;

        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;
        operands[3].imm = 31;
        return;
      }
      return aliasNYI();
    case ARM64_INS_TLBI:
      return aliasNYI();
    case ARM64_INS_TST:
      if (opcode == Opcode::AArch64_ANDSWrs ||
          opcode == Opcode::AArch64_ANDSXrs ||
          opcode == Opcode::AArch64_ANDSWri ||
          opcode == Opcode::AArch64_ANDSXri) {
        // tst rn, rm; alias for: ands zr, rn, rm
        // tst rn, #imm; alias for: ands zr, rn, #imm
        operandCount = 3;
        operands[2] = operands[1];
        operands[1] = operands[0];
        operands[1].access = CS_AC_READ;

        operands[0].type = ARM64_OP_REG;
        operands[0].access = CS_AC_WRITE;
        if (opcode == Opcode::AArch64_ANDSWrs ||
            opcode == Opcode::AArch64_ANDSWri) {
          operands[0].reg = ARM64_REG_WZR;
        } else {
          operands[0].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_UBFIZ:
      if (opcode == Opcode::AArch64_UBFMWri ||
          opcode == Opcode::AArch64_UBFMXri) {
        operands[3].imm -= 1;

        uint8_t highestBit = 63;
        if (opcode == Opcode::AArch64_UBFMWri) {
          highestBit = 31;
        }

        operands[2].imm = (-operands[2].imm) & highestBit;
        return;
      }
      return aliasNYI();
    case ARM64_INS_UBFX:
      return aliasNYI();
    case ARM64_INS_UMNEGL:
      return aliasNYI();
    case ARM64_INS_UMULL:
      return aliasNYI();
    case ARM64_INS_UXTB:
      return aliasNYI();
    case ARM64_INS_UXTH:
      return aliasNYI();
  }
}

void InstructionMetadata::aliasNYI() { id = ARM64_INS_INVALID; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
