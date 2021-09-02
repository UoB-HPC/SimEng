#include "InstructionMetadata.hh"

#include <cassert>
#include <cstring>

namespace simeng {
namespace arch {
namespace riscv {

InstructionMetadata::InstructionMetadata(const cs_insn& insn)
    : id(insn.id),
      opcode(insn.opcode),
      implicitSourceCount(insn.detail->regs_read_count),
      implicitDestinationCount(insn.detail->regs_write_count),
      //      groupCount(insn.detail->groups_count),
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
  //  std::memcpy(groups, insn.detail->groups, sizeof(uint8_t) * groupCount);
  std::memcpy(operands, insn.detail->riscv.operands,
              sizeof(cs_riscv_op) * operandCount);

  // Fix some inaccuracies in the decoded metadata
  switch (opcode) {
    case Opcode::RISCV_ADDI: {
      if (operandCount == 0 && strcmp(mnemonic, "nop") == 0) {
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = 1;

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "mv") == 0) {
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
    }
    case Opcode::RISCV_ADDIW: {
      if (operandCount == 2 && strcmp(mnemonic, "sext.w") == 0) {
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
    }
    case Opcode::RISCV_SUB: {
      if (operandCount == 2 && strcmp(mnemonic, "neg") == 0) {
        includeZeroRegisterPosOne();
      }
    }
    case Opcode::RISCV_SUBW: {
      if (operandCount == 2 && strcmp(mnemonic, "negw") == 0) {
        includeZeroRegisterPosOne();
      }
    }
    case Opcode::RISCV_XORI: {
      if (operandCount == 2 && strcmp(mnemonic, "not") == 0) {
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = -1;

        operandCount = 3;
      }
    }
    case Opcode::RISCV_SLTIU: {
      if (operandCount == 2 && strcmp(mnemonic, "seqz") == 0) {
        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 1;

        operandCount = 3;
      }
    }
    case Opcode::RISCV_SLTU: {
      if (operandCount == 2 && strcmp(mnemonic, "snez") == 0) {
        includeZeroRegisterPosOne();
      }
    }
    case Opcode::RISCV_SLT: {
      if (operandCount == 2 && strcmp(mnemonic, "sltz") == 0) {
        operands[2].type = RISCV_OP_REG;
        operands[2].reg = 1;

        operandCount = 3;
      } else if (operandCount == 2 && strcmp(mnemonic, "sgtz") == 0) {
        includeZeroRegisterPosOne();
      }
    }
    case Opcode::RISCV_JALR: {
      if (operandCount == 0 &&
          strcmp(mnemonic, "ret") == 0) {  // jalr zero, ra, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1].type = RISCV_OP_REG;
        operands[1].reg = 2;

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 &&
                 strcmp(mnemonic, "jr") == 0) {  // jalr zero, ra, 0
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 1;

        operands[1] = insn.detail->riscv.operands[0];

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      } else if (operandCount == 1 && strcmp(mnemonic, "jalr") == 0) {
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
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 2;

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = insn.detail->riscv.operands[0].imm;

        operandCount = 2;
      } else if (operandCount == 1 && strcmp(mnemonic, "j") == 0) {
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
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_BNE: {
      if (operandCount == 2 && strcmp(mnemonic, "bnez") == 0) {
        includeZeroRegisterPosOne();
      }
      break;
    }
    case Opcode::RISCV_BLT: {
      if (operandCount == 2 && strcmp(mnemonic, "bltz") == 0) {
        includeZeroRegisterPosOne();
      } else if (operandCount == 2 && strcmp(mnemonic, "bgtz") == 0) {
        includeZeroRegisterPosZero();
      }
      break;
    }
    case Opcode::RISCV_BGE: {
      if (operandCount == 2 && strcmp(mnemonic, "blez") == 0) {
        includeZeroRegisterPosZero();
      } else if (operandCount == 2 && strcmp(mnemonic, "bgez") == 0) {
        includeZeroRegisterPosOne();
      }
      break;
    }
  }

  //  revertAliasing();
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding,
                                         uint8_t bytes)
    : id(RISCV_INS_INVALID),
      opcode(Opcode::RISCV_INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      groupCount(0),
      operandCount(0) {
  assert(bytes <= sizeof(encoding));
  std::memcpy(encoding, invalidEncoding, bytes);
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

// void InstructionMetadata::revertAliasing() {
//  // Check mnemonics known to be aliases and see if their opcode matches
//  // something else
//  switch (id) {
//  }
//}

void InstructionMetadata::aliasNYI() { id = RISCV_INS_INVALID; }

void InstructionMetadata::includeZeroRegisterPosOne() {
  operands[2] = operands[1];

  operands[1].type = RISCV_OP_REG;
  operands[1].reg = 1;

  operandCount = 3;
}

void InstructionMetadata::includeZeroRegisterPosZero() {
  operands[2] = operands[1];
  operands[1] = operands[0];

  operands[0].type = RISCV_OP_REG;
  operands[0].reg = 1;

  operandCount = 3;
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng