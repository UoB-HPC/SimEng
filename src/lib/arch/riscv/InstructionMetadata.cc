#include "InstructionMetadata.hh"

#include <cassert>
#include <cstring>
#include <iostream>

namespace simeng {
namespace arch {
namespace riscv {

InstructionMetadata::InstructionMetadata(const cs_insn& insn)
    : id(insn.id),
      opcode(insn.opcode),
      implicitSourceCount(insn.detail->regs_read_count),
      implicitDestinationCount(insn.detail->regs_write_count),
//      groupCount(insn.detail->groups_count),
//      cc(insn.detail->arm64.cc - 1),
//      setsFlags(insn.detail->arm64.update_flags),
//      writeback(insn.detail->arm64.writeback),
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
    case Opcode::RISCV_JALR:
      if (operandCount == 1) {
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 2;

        operands[1] = insn.detail->riscv.operands[0];

        operands[2].type = RISCV_OP_IMM;
        operands[2].imm = 0;

        operandCount = 3;
      }
      break;
    case Opcode::RISCV_JAL:
      if (operandCount == 1) {
        operands[0].type = RISCV_OP_REG;
        operands[0].reg = 2;

        operands[1].type = RISCV_OP_IMM;
        operands[1].imm = insn.detail->riscv.operands[0].imm;

        operandCount = 2;
      }
      break;
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
//      setsFlags(false),
//      writeback(false),
      operandCount(0) {
  assert(bytes <= sizeof(encoding));
  std::memcpy(encoding, invalidEncoding, bytes);
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

//void InstructionMetadata::revertAliasing() {
//  // Check mnemonics known to be aliases and see if their opcode matches
//  // something else
//  switch (id) {
//  }
//}

void InstructionMetadata::aliasNYI() { id = RISCV_INS_INVALID; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng