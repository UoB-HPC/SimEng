#include "InstructionMetadata.hh"

#include <cassert>
#include <cstring>
#include <iostream>

#include "simeng/arch/riscv/Architecture.hh"

namespace simeng {
namespace arch {
namespace riscv {

InstructionMetadata::InstructionMetadata(const cs_insn& insn)
    : id(insn.id),
      opcode(insn.opcode),
      implicitSourceCount(insn.detail->regs_read_count),
      implicitDestinationCount(insn.detail->regs_write_count),
      operandCount(insn.detail->riscv.op_count) {
  std::memcpy(encoding, insn.bytes, sizeof(encoding));
  // Copy printed output
  std::strncpy(mnemonic, insn.mnemonic, CS_MNEMONIC_SIZE);
  operandStr = std::string(insn.op_str);

  // Copy register/group/operand information
  std::memcpy(implicitSources, insn.detail->regs_read,
              sizeof(uint16_t) * implicitSourceCount);
  std::memcpy(implicitDestinations, insn.detail->regs_write,
              sizeof(uint16_t) * implicitDestinationCount);
  std::memcpy(operands, insn.detail->riscv.operands,
              sizeof(cs_riscv_op) * operandCount);

  alterPseudoInstructions(insn);
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding,
                                         uint8_t bytes)
    : id(RISCV_INS_INVALID),
      opcode(Opcode::RISCV_INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      operandCount(0) {
  assert(bytes <= sizeof(encoding));
  std::memcpy(encoding, invalidEncoding, bytes);
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

void InstructionMetadata::alterPseudoInstructions(const cs_insn& insn) {
  // Check for pseudoinstructions and alter operands given by capstone to match
  // specified functionality.
  // The format of comments below is:
  // capstone gives -> we return
  // _ represents operand not provided
  switch (opcode) {
    case Opcode::RISCV_ADDI: {
      if (operandCount == 0 && strcmp(mnemonic, "nop") == 0) {
        // nop is pseudo of ADDI x0, x0, 0
        // ADDI _, _, _-> ADDI x0, x0, 0
        // reg set to 1 to reflect capstones 1 indexed output
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = 1;

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "mv") == 0) {
        // mv Rd, Rs is pseudo of ADDI Rd, Rs, 0
        // ADDI Rd, Rs, _ -> ADDI Rd, Rs, 0
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_ADDIW: {
      if (operandCount == 2 && strcmp(mnemonic, "sext.w") == 0) {
        // sext.w Rd, Rs is pseudo of ADDIW Rd, Rs, 0
        // ADDIW Rd, Rs, _ -> ADDIW Rd, Rs, 0
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_SUB: {
      if (operandCount == 2 && strcmp(mnemonic, "neg") == 0) {
        // neg Rd, Rs is pseudo of SUB Rd, x0, Rs
        // SUB Rd, Rs, _ -> SUB Rd, x0, Rs
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_SUBW: {
      if (operandCount == 2 && strcmp(mnemonic, "negw") == 0) {
        // negw Rs, Rs is pseudo of SUBW Rd, x0, Rs
        // SUBW Rd, Rs, _ -> SUBW Rd, x0, Rs
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_XORI: {
      if (operandCount == 2 && strcmp(mnemonic, "not") == 0) {
        // not Rd, Rs is pseudo of XORI Rd, Rs, -1
        // XORI Rd, Rs, _ -> XORI Rd, Rs, -1
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = -1;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_SLTIU: {
      if (operandCount == 2 && strcmp(mnemonic, "seqz") == 0) {
        // seqz Rd, Rs is pseudo of SLTIU Rd, Rs, 1
        // SLTIU Rd, Rs, _ -> SLTIU Rd, Rs, 1
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 1;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_SLTU: {
      if (operandCount == 2 && strcmp(mnemonic, "snez") == 0) {
        // snez Rd, Rs is pseudo of SLTU Rd, x0, Rs
        // SLTU Rd, Rs, _ -> SLTU Rd, x0, Rs
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_SLT: {
      if (operandCount == 2 && strcmp(mnemonic, "sltz") == 0) {
        // sltz Rd, Rs is pseudo of SLT Rd, Rs, x0
        // SLT Rd, Rs, _ -> SLT Rd, Rs, x0
        operands[2].type = RISCV_OP_REG;
        operands[2].reg = 1;

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "sgtz") == 0) {
        // sgtz Rd, Rs is pseudo of SLT Rd, x0, Rs
        // SLT Rd, Rs, _ -> SLT Rd, x0, Rs
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_JALR: {
      if (operandCount == 0 && strcmp(mnemonic, "ret") == 0) {
        // ret is pseudo of JALR x0, x1, 0
        // JALR _, _, _ -> JALR x0, x1, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = 2;

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 && strcmp(mnemonic, "jr") == 0) {
        // jr Rs is pseudo of JALR x0, Rs, 0
        // JALR Rs, _, _ -> JALR x0, Rs, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1] = insn.detail->riscv.operands[0];

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 && strcmp(mnemonic, "jalr") == 0) {
        // jalr Rs is pseudo of JALR x1, Rs, 0
        // JALR Rs, _, _ -> JALR x1, Rs, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 2;

        operands[1] = insn.detail->riscv.operands[0];

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_JAL: {
      if (operandCount == 1 && strcmp(mnemonic, "jal") == 0) {
        // jal offset is pseudo of JAL x1, offset
        // JAL offset, _ -> JAL x1, offset
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 2;

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = insn.detail->riscv.operands[0].imm;

        operandCount = 2;
      } else if (operandCount == 1 && strcmp(mnemonic, "j") == 0) {
        // j offset is pseudo of JAL x0, offset
        // JAL offset, _ -> JAL x0, offset
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = insn.detail->riscv.operands[0].imm;

        operandCount = 2;
      }
      break;
    }
    case Opcode::RISCV_BEQ: {
      if (operandCount == 2 && strcmp(mnemonic, "beqz") == 0) {
        // jalr Rs is pseudo of JALR x1, Rs, 0
        // JALR Rs, _, _ -> JALR x1, Rs, 0
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_BNE: {
      if (operandCount == 2 && strcmp(mnemonic, "bnez") == 0) {
        // bnez Rs, offset is pseudo of BNE Rs, x0, offset
        // BNE Rs, offset, _ -> BNE Rs, x0, offset
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_BLT: {
      if (operandCount == 2 && strcmp(mnemonic, "bltz") == 0) {
        // bltz Rs, offset is pseudo of BLT Rs, x0, offset
        // BLT Rs, offset, _ -> BLT Rs, x0, offset
        includeZeroRegisterPosOne();
      } else if (operandCount == 2 && strcmp(mnemonic, "bgtz") == 0) {
        // bgtz Rs, offset is pseudo of BLT x0, Rs, offset
        // BLT Rs, offset, _ -> BLT x0, Rs, offset
        includeZeroRegisterPosZero();
      }
      break;
    }
    case Opcode::RISCV_BGE: {
      if (operandCount == 2 && strcmp(mnemonic, "blez") == 0) {
        // blez Rs, offset is pseudo of BGE x0, Rs, offset
        // BGE Rs, offset, _ -> BGE x0, Rs, offset
        includeZeroRegisterPosZero();
      } else if (operandCount == 2 && strcmp(mnemonic, "bgez") == 0) {
        // bgez Rs, offset is pseudo of BGE Rs, x0, offset
        // BGE Rs, offset, _ -> BGE Rs, x0, offset
        includeZeroRegisterPosOne();
      }
      break;
    }

    case Opcode::RISCV_CSRRS: {
      if (operandCount == 1 && strcmp(mnemonic, "frflags") == 0) {
        // frflags Rs is pseudo of CSRRS Rs, fflags, zero (Read FP exception
        // flags) CSRRS Rs, _, _ -> CSRRS Rs, fflags, zero
        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].reg = RISCV_SYSREG_FFLAGS;  // fflags address

        operands[2].type = RISCV_OP_REG;
        operands[2].reg = 1;

        operandCount = 3;
      } else if (strcmp(mnemonic, "rdinstret") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "rdinstret");
      } else if (strcmp(mnemonic, "rdcycle") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "rdcycle");
      } else if (strcmp(mnemonic, "rdtime") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "rdtime");
      } else if (strcmp(mnemonic, "csrr") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "csrr");
      } else if (strcmp(mnemonic, "csrs") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "csrs");
      } else if (strcmp(mnemonic, "frcsr") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "rdtime");
      } else if (operandCount == 1 && strcmp(mnemonic, "frrm") == 0) {
        // frrm Rs is pseudo of CSRRS Rs, frm, zero (Read FP rounding mode)
        // CSRRS Rs, _, _ -> CSRRS Rs, frm, zero
        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].reg = RISCV_SYSREG_FRM;  // frm address

        operands[2].type = RISCV_OP_REG;
        operands[2].reg = 1;

        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_CSRRW: {
      if (operandCount == 1 && strcmp(mnemonic, "fsflags") == 0) {
        // fsflags Rs is pseudo of CSRRW zero, fflags, rs (Write FP exception
        // flags)
        // CSRRW Rs, _, _ -> CSRRW zero, fflags, Rs
        operands[2] = operands[0];

        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].reg = RISCV_SYSREG_FFLAGS;  // fflags address

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "fsflags") == 0) {
        // fsflags R1, R2 is pseudo of CSRRW r1, fflags, rs (Write FP exception
        // flags)
        // CSRRW R1, R2, _ -> CSRRW R1, fflags, R2
        operands[2] = operands[1];

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].reg = RISCV_SYSREG_FFLAGS;  // fflags address

        operandCount = 3;
      } else if (strcmp(mnemonic, "csrw") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "csrw");
      } else if (strcmp(mnemonic, "fscsr") == 0) {
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "fscsr");
      } else if (strcmp(mnemonic, "fscsr") == 0) {
        // 2 pseudoinstructions with same name but different number of registers
        assert(false &&
               "[SimEng::InstructionMetadata] Unimplemented psuedoinstruction "
               "fscsr");
      } else if (operandCount == 1 && strcmp(mnemonic, "fsrm") == 0) {
        // fsrm Rs is pseudo of CSRRW zero, frm, rs (Write FP rounding mode)
        // CSRRW Rs, _, _ -> CSRRW zero, frm, Rs
        operands[2] = operands[0];

        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].reg = RISCV_SYSREG_FRM;  // frm address

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "fsrm") == 0) {
        // fsrm R1, R2 is pseudo of CSRRW R1, frm, R2 (Write FP rounding mode)
        // CSRRW R1, R2, _ -> CSRRW R1, frm, R2
        operands[2] = operands[1];

        operands[1].type = RISCV_OP_IMM;
        operands[1].reg = RISCV_SYSREG_FRM;

        operandCount = 3;
      }
      break;
    }

    case Opcode::RISCV_FSGNJ_S: {
      if (operandCount == 2 && strcmp(mnemonic, "fmv.s") == 0) {
        // fmv.s rd, rs is pseudo of fsgnj.s rd, rs, rs (Copy single-precision
        // register)
        // fsgnj.s Rd, Rs, _ -> fsgnj.s Rd, Rs, Rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_FSGNJX_S: {
      if (operandCount == 2 && strcmp(mnemonic, "fabs.s") == 0) {
        // fabs.s rd, rs is pseudo of  fsgnjx.s rd, rs, rs (Single-precision
        // absolute value)
        // fsgnjx.s rd, rs, _ -> fsgnjx.s rd, rs, rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_FSGNJN_S: {
      if (operandCount == 2 && strcmp(mnemonic, "fneg.s") == 0) {
        // fneg.s rd, rs is pseudo of  fsgnjn.s rd, rs, rs (Single-precision
        // negate)
        // fsgnjn.s rd, rs, _ -> fsgnjn.s rd, rs, rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }

    case Opcode::RISCV_FSGNJ_D: {
      if (operandCount == 2 && strcmp(mnemonic, "fmv.d") == 0) {
        // fmv.d rd, rs is pseudo of fsgnj.d rd, rs, rs (Copy double-precision
        // register)
        // fsgnj.d Rd, Rs, _ -> fsgnj.d Rd, Rs, Rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_FSGNJX_D: {
      if (operandCount == 2 && strcmp(mnemonic, "fabs.d") == 0) {
        // fabs.d rd, rs is pseudo of  fsgnjx.d rd, rs, rs (Double-precision
        // absolute value)
        // fsgnjx.d rd, rs, _ -> fsgnjx.d rd, rs, rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }
    case Opcode::RISCV_FSGNJN_D: {
      // fneg.d rd, rs, fsgnjn.d rd, rs, rs, Double-precision negate
      if (operandCount == 2 && strcmp(mnemonic, "fneg.d") == 0) {
        // fneg.d rd, rs is pseudo of  fsgnjn.d rd, rs, rs (Double-precision
        // neagte)
        // fsgnjn.d rd, rs, _ -> fsgnjn.d rd, rs, rs
        operands[2] = operands[1];
        operandCount = 3;
      }
      break;
    }
  }
}

void InstructionMetadata::aliasNYI() { id = RISCV_INS_INVALID; }

void InstructionMetadata::includeZeroRegisterPosOne() {
  // Given register sequence {Op_a, Op_b , _} return {Op_a, x0, Op_b}
  operands[2] = operands[1];

  operands[1].type = RISCV_OP_REG;
  operands[1].reg = 1;

  operandCount = 3;
}

void InstructionMetadata::includeZeroRegisterPosZero() {
  // Given register sequence {Op_a, Op_b, _} return {x0, Op_a, Op_b}
  operands[2] = operands[1];
  operands[1] = operands[0];

  operands[0].type = RISCV_OP_REG;
  operands[0].reg = 1;

  operandCount = 3;
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng