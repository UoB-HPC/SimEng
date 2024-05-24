#include "InstructionMetadata.hh"

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
  // Populate 'encoding' field with correct bytes dependent on whether this is a
  // compressed instruction
  insnLengthBytes_ = insn.size;
  std::memset(encoding, 0, 4);
  std::memcpy(encoding, insn.bytes, insnLengthBytes_);

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

  convertCompressedInstruction(insn);
  alterPseudoInstructions(insn);
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding,
                                         uint8_t bytes)
    : id(RISCV_INS_INVALID),
      opcode(Opcode::RISCV_INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      operandCount(0),
      insnLengthBytes_(bytes) {
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
        operands[0].reg = RISCV_REG_ZERO;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = RISCV_REG_ZERO;

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
        operands[2].reg = RISCV_REG_ZERO;

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
        operands[0].reg = RISCV_REG_ZERO;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = RISCV_REG_RA;

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 && strcmp(mnemonic, "jr") == 0) {
        // jr Rs is pseudo of JALR x0, Rs, 0
        // JALR Rs, _, _ -> JALR x0, Rs, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = RISCV_REG_ZERO;

        operands[1] = insn.detail->riscv.operands[0];

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 && strcmp(mnemonic, "jalr") == 0) {
        // jalr Rs is pseudo of JALR x1, Rs, 0
        // JALR Rs, _, _ -> JALR x1, Rs, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = RISCV_REG_RA;

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
        operands[0].reg = RISCV_REG_RA;

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = insn.detail->riscv.operands[0].imm;

        operandCount = 2;
      } else if (operandCount == 1 && strcmp(mnemonic, "j") == 0) {
        // j offset is pseudo of JAL x0, offset
        // JAL offset, _ -> JAL x0, offset
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = RISCV_REG_ZERO;

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
        operands[1].imm = RISCV_SYSREG_FFLAGS;  // fflags address

        operands[2].type = RISCV_OP_REG;
        operands[2].reg = RISCV_REG_ZERO;

        operandCount = 3;
      } else if (strcmp(mnemonic, "rdinstret") == 0) {
        return aliasNYI();
      } else if (strcmp(mnemonic, "rdcycle") == 0) {
        return aliasNYI();
      } else if (strcmp(mnemonic, "rdtime") == 0) {
        return aliasNYI();
      } else if (strcmp(mnemonic, "csrr") == 0) {
        return aliasNYI();
      } else if (strcmp(mnemonic, "csrs") == 0) {
        return aliasNYI();
      } else if (strcmp(mnemonic, "frcsr") == 0) {
        return aliasNYI();
      } else if (operandCount == 1 && strcmp(mnemonic, "frrm") == 0) {
        // frrm Rs is pseudo of CSRRS Rs, frm, zero (Read FP rounding mode)
        // CSRRS Rs, _, _ -> CSRRS Rs, frm, zero
        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].imm = RISCV_SYSREG_FRM;  // frm address

        operands[2].type = RISCV_OP_REG;
        operands[2].reg = RISCV_REG_ZERO;

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
        operands[0].reg = RISCV_REG_ZERO;

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].imm = RISCV_SYSREG_FFLAGS;  // fflags address

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "fsflags") == 0) {
        // fsflags R1, R2 is pseudo of CSRRW r1, fflags, rs (Write FP exception
        // flags)
        // CSRRW R1, R2, _ -> CSRRW R1, fflags, R2
        operands[2] = operands[1];

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].imm = RISCV_SYSREG_FFLAGS;  // fflags address

        operandCount = 3;
      } else if (strcmp(mnemonic, "csrw") == 0) {
        return aliasNYI();
      } else if (operandCount == 1 && strcmp(mnemonic, "fscsr") == 0) {
        return aliasNYI();
      } else if (operandCount == 2 && strcmp(mnemonic, "fscsr") == 0) {
        return aliasNYI();
        // 2 pseudoinstructions with same name but different number of registers
      } else if (operandCount == 1 && strcmp(mnemonic, "fsrm") == 0) {
        // fsrm Rs is pseudo of CSRRW zero, frm, rs (Write FP rounding mode)
        // CSRRW Rs, _, _ -> CSRRW zero, frm, Rs
        operands[2] = operands[0];

        operands[0].type = RISCV_OP_REG;
        operands[0].reg = RISCV_REG_ZERO;

        operands[1].type =
            RISCV_OP_IMM;  // TODO needs to become reg when Capstone updated
        operands[1].imm = RISCV_SYSREG_FRM;  // frm address

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "fsrm") == 0) {
        // fsrm R1, R2 is pseudo of CSRRW R1, frm, R2 (Write FP rounding mode)
        // CSRRW R1, R2, _ -> CSRRW R1, frm, R2
        operands[2] = operands[1];

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = RISCV_SYSREG_FRM;

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

void InstructionMetadata::aliasNYI() {
  metadataExceptionEncountered_ = true;
  metadataException_ = InstructionException::AliasNotYetImplemented;
}

void InstructionMetadata::includeZeroRegisterPosOne() {
  // Given register sequence {Op_a, Op_b , _} return {Op_a, x0, Op_b}
  operands[2] = operands[1];

  operands[1].type = RISCV_OP_REG;
  operands[1].reg = RISCV_REG_ZERO;

  operandCount = 3;
}

void InstructionMetadata::includeZeroRegisterPosZero() {
  // Given register sequence {Op_a, Op_b, _} return {x0, Op_a, Op_b}
  operands[2] = operands[1];
  operands[1] = operands[0];

  operands[0].type = RISCV_OP_REG;
  operands[0].reg = RISCV_REG_ZERO;

  operandCount = 3;
}

void InstructionMetadata::duplicateFirstOp() {
  // Given register sequence {Op_a, Op_b, _} return {Op_a, Op_a, Op_b}
  operands[2] = operands[1];
  operands[1] = operands[0];

  operandCount = 3;
}

void InstructionMetadata::createMemOpPosOne() {
  // Given register sequence {Op_a, imm, reg} return {Op_a, mem, _}
  assert(operands[1].type == RISCV_OP_IMM &&
         "Incorrect operand type when creating memory operand");
  assert(operands[2].type == RISCV_OP_REG &&
         "Incorrect operand type when creating memory operand");

  cs_riscv_op temp;
  temp.type = RISCV_OP_MEM;
  temp.mem.base = operands[2].reg;
  temp.mem.disp = operands[1].imm;

  operands[1] = temp;

  operandCount = 2;
}

void InstructionMetadata::convertCompressedInstruction(const cs_insn& insn) {
  if (insnLengthBytes_ != 2) {
    return;
  }

  switch (insn.opcode) {
    case Opcode::RISCV_C_JR:
      // jalr x0, 0(rs1)
      // C.JR rs1, _, _ -> JALR x0, rs1, 0

      // rs1=zero is reserved
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.JR has rs1=x0 which is reserved");
      }

      opcode = Opcode::RISCV_JALR;

      operands[0].type = RISCV_OP_REG;
      operands[0].reg = RISCV_REG_ZERO;

      operands[1] = insn.detail->riscv.operands[0];

      operands[2].type = RISCV_OP_IMM;
      operands[2].imm = 0;

      operandCount = 3;

      break;
    case Opcode::RISCV_C_MV:
      // add rd, x0, rs2
      // rs2 == zero and rd == zero are hints
      // C.MV rd, rs2, _ -> ADD rd, zero, rs2

      // rs2 = zero corresponds to C.JR
      if (operands[1].type != RISCV_OP_REG ||
          operands[1].reg == RISCV_REG_ZERO) {
        illegalAlias("C.MV has rs2=x0 which is invalid");
      }

      opcode = Opcode::RISCV_ADD;

      includeZeroRegisterPosOne();

      break;
    case Opcode::RISCV_C_LDSP: {
      // TODO valid for RV64 only. Make this check once RV32 implemented
      // ld rd, offset[8:3](x2)
      // offset is immediate scaled by 8. Capstone does scaling for us

      // rd = zero is reserved
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.LDSP has rd=x0 which is reserved");
      }

      opcode = Opcode::RISCV_LD;

      // Create operand formatted like LD instruction
      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_ADDI4SPN:
      // addi rd ′ , x2, nzuimm[9:2]

      // nzuimm = zero is reserved
      if (operands[2].type != RISCV_OP_IMM || operands[2].imm == 0) {
        illegalAlias("C.ADDI4SPN has nzuimm=0 which is reserved");
      }

      opcode = Opcode::RISCV_ADDI;
      // All operands correct
      break;
    case Opcode::RISCV_C_LI:
      // addi rd, x0, imm[5:0]
      // C.LI rd, imm, _ -> addi rd, zero, imm

      // rd = zero encodes hints
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias(
            "C.LI has rd=x0 which encodes hints which currently aren't "
            "implemented");
      }

      opcode = Opcode::RISCV_ADDI;

      includeZeroRegisterPosOne();

      break;
    case Opcode::RISCV_C_ADDI16SP:
      // Opcode shared with C.LUI but has Rd = x2
      // addi x2, x2, nzimm[9:4]
      // C.ADDI16SP sp, imm, _ -> addi sp, sp, imm

      // nzimm = zero is reserved
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias("C.ADDI16SP has nzimm=0 which is reserved");
      }

      opcode = Opcode::RISCV_ADDI;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_SLLI:
      // slli rd, rd, shamt[5:0]
      //
      // "For RV32C, shamt[5] must be zero; the code points with shamt[5]=1 are
      // reserved for custom extensions. For RV32C and RV64C, the shift amount
      // must be non-zero; the code points with shamt=0 are HINTs. For all base
      // ISAs, the code points with rd=x0 are HINTs, except those with
      // shamt[5]=1 in RV32C." - Spec page 107
      //
      // C.SLLI rd, shamt, _ -> slli rd, rd, shamt

      // shamt = zero is reserved for hints
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias(
            "C.SLLI has shamt=0 which is reserved for hints which currently "
            "aren't implemented");
      }

      // rd = zero encodes hints
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias(
            "C.SLLI has rd=x0 which is reserved for hints  which currently "
            "aren't implemented");
      }

      opcode = Opcode::RISCV_SLLI;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_SDSP: {
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // sd rs2, offset[8:3](x2)

      opcode = Opcode::RISCV_SD;

      // Create operand formatted like SD instruction
      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_SWSP: {
      // sw rs2, offset[7:2](x2)
      opcode = Opcode::RISCV_SW;

      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_ADD:
      // add rd, rd, rs2
      //
      // "code points with rs2=x0 correspond
      // to the C.JALR and C.EBREAK
      // instructions. The code points with
      // rs2̸=x0 and rd=x0 are HINTs." - Spec page 108
      //
      // C.ADD rd, rs2, _ -> add rd, rd, rs2

      // rs2 = zero corresponds to C.JALR and C.EBREAK
      if (operands[1].type != RISCV_OP_REG ||
          operands[1].reg == RISCV_REG_ZERO) {
        illegalAlias("C.ADD has rs2=x0 which is invalid");
      }

      // rs2 = zero AND rd = zero are reserved for hints
      if ((operands[0].type != RISCV_OP_REG ||
           operands[0].reg == RISCV_REG_ZERO) &&
          (operands[1].type != RISCV_OP_REG ||
           operands[1].reg == RISCV_REG_ZERO)) {
        illegalAlias(
            "C.ADD has rs2=x0 and rd=x0 which is reserved for hints which "
            "currently aren't implemented");
      }

      opcode = Opcode::RISCV_ADD;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_LD: {
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // ld rd ′ , offset[7:3](rs1 ′)

      opcode = Opcode::RISCV_LD;

      // Create operand formatted like LD instruction
      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_ADDI: {
      // addi rd, rd, nzimm[5:0]
      // C.ADDI rd, imm, _ -> addi rd, rd, imm

      // rd = zero encodes C.NOP
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.ADDI has rd=x0 which is invalid");
      }

      // nzimm = zero is reserved for hints
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias(
            "C.ADDI has nzimm=0 which is reserved for hints which currently "
            "aren't implemented");
      }

      opcode = Opcode::RISCV_ADDI;

      duplicateFirstOp();

      break;
    }
    case Opcode::RISCV_C_BNEZ:
      // bne rs1 ′ , x0, offset[8:1]
      // C.BNEZ rs1, imm, _ -> bne rs1, zero, imm
      opcode = Opcode::RISCV_BNE;

      includeZeroRegisterPosOne();

      break;
    case Opcode::RISCV_C_SD: {
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // sd rs2 ′ , offset[7:3](rs1 ′)

      opcode = Opcode::RISCV_SD;
      // Create operand formatted like SD instruction
      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_BEQZ:
      // beq rs1 ′ , x0, offset[8:1]
      // C.BEQZ rs1, imm, _ -> beq rs1, zero, imm
      opcode = Opcode::RISCV_BEQ;

      includeZeroRegisterPosOne();

      break;
    case Opcode::RISCV_C_ANDI:
      // andi rd ′, rd ′ , imm[5:0]
      // C.ANDI rd, imm, _ -> andi rd, rd, imm
      opcode = Opcode::RISCV_ANDI;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_LUI:
      // lui rd, nzimm[17:12]

      // nzimm = zero is reserved
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias("C.LUI has nzimm=0 which is reserved");
      }

      // rd = zero is reserved for hints
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias(
            "C.LUI has rd=x0 which is reserved for hints which currently "
            "aren't implemented");
      }

      // rd = x2 encodes C.ADDI16SP
      if (operands[0].type != RISCV_OP_REG || operands[0].reg == RISCV_REG_SP) {
        illegalAlias("C.LUI has rd=x2 which is invalid");
      }

      opcode = Opcode::RISCV_LUI;
      // All operands correct
      break;
    case Opcode::RISCV_C_LWSP: {
      // lw rd, offset[7:2](x2)

      // rd = zero is reserved
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.LWSP has rd=x0 which is reserved");
      }

      opcode = Opcode::RISCV_LW;

      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_FLDSP:
      // TODO RV32DC/RV64DC-only once RV32 implemented
      // fld rd, offset[8:3](x2)
      opcode = Opcode::RISCV_FLD;

      createMemOpPosOne();

      break;
    case Opcode::RISCV_C_SW: {
      // sw rs2 ′, offset[6:2](rs1 ′)

      opcode = Opcode::RISCV_SW;

      createMemOpPosOne();

      break;
    }
    case Opcode::RISCV_C_J:
      // jal x0, offset[11:1]
      // C.J imm, _ -> jal zero, imm
      opcode = Opcode::RISCV_JAL;

      operands[1] = operands[0];

      operands[0].type = RISCV_OP_REG;
      operands[0].reg = RISCV_REG_ZERO;

      operandCount = 2;

      break;
    case Opcode::RISCV_C_ADDIW:
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // addiw rd, rd, imm[5:0]
      // C.ADDIW rd, imm, _ -> addiw rd, rd, imm

      // "The immediate can be zero for C.ADDIW, where this corresponds to
      // [pseudoinstruction] sext.w rd" - Spec page 106
      // rd = zero is reserved
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.ADDIW has rd=x0 which is reserved");
      }

      opcode = Opcode::RISCV_ADDIW;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_SUB:
      // sub rd ′ , rd ′ , rs2 ′
      // C.SUB rd, rs2, -> sub rd, rd, rs2
      opcode = Opcode::RISCV_SUB;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_LW:
      // lw rd ′ , offset[6:2](rs1 ′ )

      opcode = Opcode::RISCV_LW;

      createMemOpPosOne();

      break;
    case Opcode::RISCV_C_SRLI:
      // srli rd ′ , rd ′ , shamt[5:0]
      // C.SRLI rd, imm, _ -> srli rd, rd, imm

      // shamt = zero is reserved for hints
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias(
            "C.SRLI has shamt=0 which is reserved for hints which currently "
            "aren't implemented");
      }

      opcode = Opcode::RISCV_SRLI;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_ADDW:
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // addw rd ′ , rd ′ , rs2 ′
      // C.ADDW rd, rs2, _ -> addw rd, rd, rs2
      opcode = Opcode::RISCV_ADDW;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_AND:
      // and rd ′ , rd ′ , rs2 ′
      // C.AND rd, rs2, _ -> and rd, rd, rs2
      opcode = Opcode::RISCV_AND;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_OR:
      // or rd ′ , rd ′ , rs2 ′
      // C.OR rd, rs2, _ ->  or rd, rd, rs2

      opcode = Opcode::RISCV_OR;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_JALR:
      // jalr x1, 0(rs1)
      // C.JALR rs1, _, _ -> jalr x1, rs1, 0

      // rs1=zero corresponds to C.EBREAK instruction
      if (operands[0].type != RISCV_OP_REG ||
          operands[0].reg == RISCV_REG_ZERO) {
        illegalAlias("C.JALR has rs1=x0 which is invalid");
      }

      opcode = Opcode::RISCV_JALR;

      operands[1] = operands[0];

      operands[0].reg = RISCV_REG_RA;

      operands[2].type = RISCV_OP_IMM;
      operands[2].imm = 0;

      operandCount = 3;

      break;
    case Opcode::RISCV_C_XOR:
      // xor rd ′ , rd ′ , rs2 ′
      // C.XOR rd, rs2, _ -> xor rd, rd, rs2

      opcode = Opcode::RISCV_XOR;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_SRAI:
      // srai rd ′ , rd ′ , shamt[5:0]
      // C.SRAI rd, imm, _ -> srai rd, rd, imm

      // shamt = zero is reserved for hints
      if (operands[1].type != RISCV_OP_IMM || operands[1].imm == 0) {
        illegalAlias(
            "C.SRAI has shamt=0 which is reserved for hints which currently "
            "aren't implemented");
      }

      opcode = Opcode::RISCV_SRAI;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_FSD:
      // TODO rv64dc ONLY, make check for this once RV32 implemented
      // fsd rs2 ′, offset[7:3](rs1 ′)

      opcode = Opcode::RISCV_FSD;

      createMemOpPosOne();

      break;
    case Opcode::RISCV_C_FLD:
      // TODO rv64dc ONLY, make check for this once RV32 implemented
      // fld rd ′, offset[7:3](rs1 ′)

      opcode = Opcode::RISCV_FLD;

      createMemOpPosOne();

      break;
    case Opcode::RISCV_C_FSDSP:
      // TODO rv64dc ONLY, make check for this once RV32 implemented
      // fsd rs2, offset[8:3](x2)

      opcode = Opcode::RISCV_FSD;

      createMemOpPosOne();

      break;
    case Opcode::RISCV_C_SUBW:
      // TODO rv64 ONLY, make check for this once RV32 implemented
      // subw rd ′ , rd ′ , rs2 ′
      // C.SUBW rd, rs2, _ -> subw rd, rd, rs2

      opcode = Opcode::RISCV_SUBW;

      duplicateFirstOp();

      break;
    case Opcode::RISCV_C_NOP:
      // nop
      // C.NOP _, _, _-> addi x0, x0, 0

      // TODO imm != zero is reserved for hints. Capstone doesn't give this
      // value so can't be checked

      opcode = Opcode::RISCV_ADDI;

      // Duplicate implementation of nop pseudoinstruction
      operands[0].type = RISCV_OP_REG;
      operands[0].reg = RISCV_REG_ZERO;

      operands[1].type = RISCV_OP_REG;
      operands[1].reg = RISCV_REG_ZERO;

      operands[2].type = RISCV_OP_IMM;
      operands[2].imm = 0;

      operandCount = 3;

      break;
    case Opcode::RISCV_C_EBREAK:
      // ebreak

      opcode = Opcode::RISCV_EBREAK;

      break;
    default:
      // Unimplemented compressed instruction, raise exception
      aliasNYI();
      break;
  }
}
void InstructionMetadata::illegalAlias(std::string info) {
  metadataExceptionEncountered_ = true;
  metadataException_ = InstructionException::IllegalInstruction;
  exceptionString = info;
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng