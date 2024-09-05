#include "InstructionMetadata.hh"

#include <cassert>
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
      cc(insn.detail->aarch64.cc),
      setsFlags(insn.detail->aarch64.update_flags),
      isAlias(insn.is_alias),
      operandCount(insn.detail->aarch64.op_count) {
  std::memcpy(encoding, insn.bytes, sizeof(encoding));
  // Copy printed output
  std::strncpy(mnemonic, insn.mnemonic, CS_MNEMONIC_SIZE);
  operandStr = std::string(insn.op_str);

  // Copy register/group/operand information
  std::memcpy(implicitSources, insn.detail->regs_read,
              sizeof(uint16_t) * implicitSourceCount);
  std::memcpy(implicitDestinations, insn.detail->regs_write,
              sizeof(uint16_t) * implicitDestinationCount);
  std::memcpy(groups, insn.detail->groups, sizeof(uint8_t) * groupCount);
  std::memcpy(operands, insn.detail->aarch64.operands,
              sizeof(cs_aarch64_op) * operandCount);

  // Fix some inaccuracies in the decoded metadata
  switch (opcode) {
    case Opcode::AArch64_ADR_LSL_ZZZ_D_0:  // example bytecode = c8a0e704
    case Opcode::AArch64_ADR_LSL_ZZZ_D_1:
    case Opcode::AArch64_ADR_LSL_ZZZ_D_2:
    case Opcode::AArch64_ADR_LSL_ZZZ_D_3:
    case Opcode::AArch64_ADR_LSL_ZZZ_S_0:
    case Opcode::AArch64_ADR_LSL_ZZZ_S_1:
    case Opcode::AArch64_ADR_LSL_ZZZ_S_2:
    case Opcode::AArch64_ADR_LSL_ZZZ_S_3: {
      // Change the last 2 Z-regs from one MEM operand to two REG operands
      operandCount = 3;
      operands[1].type = AARCH64_OP_REG;
      operands[1].access = CS_AC_READ;
      operands[1].reg = operands[1].mem.base;
      operands[2].type = AARCH64_OP_REG;
      operands[2].access = CS_AC_READ;
      operands[2].reg = operands[1].mem.index;
      operands[2].vas = operands[1].vas;
      operands[2].shift = operands[1].shift;
      break;
    }
    case Opcode::AArch64_AND_ZPmZ_D:  // Example bytecode - 4901da04
    case Opcode::AArch64_AND_ZPmZ_H:
    case Opcode::AArch64_AND_ZPmZ_S:
    case Opcode::AArch64_AND_ZPmZ_B:
      // Incorrect defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    case Opcode::AArch64_CASALW:  // Example bbytecode - 02fce188
    case Opcode::AArch64_CASALX:
      // Correct access types
      operandCount = 3;
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_ADD_ZI_B:  // Example bytecode - 00c12025
    case Opcode::AArch64_ADD_ZI_D:
    case Opcode::AArch64_ADD_ZI_H:
    case Opcode::AArch64_ADD_ZI_S: {
      // Incorrect access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      // If LSL #8 is present then immediate is not properly set.
      // LSL is automatically applied to the imm for these instructions
      std::string tmpOpStr(operandStr.substr(operandStr.find("#") + 1));
      if (tmpOpStr[1] == 'x') {
        operands[2].imm = static_cast<uint64_t>(std::stoi(tmpOpStr, 0, 16));
      }
      break;
    }
    case Opcode::AArch64_SMAX_ZI_B:
    case Opcode::AArch64_SMAX_ZI_D:
    case Opcode::AArch64_SMAX_ZI_H:
    case Opcode::AArch64_SMAX_ZI_S:  // Example bytecode - 03c0a825
    case Opcode::AArch64_AND_ZI:     // Example bytecode - 00068005
      // Incorrect access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_FSUB_ZPmI_D:
    case Opcode::AArch64_FSUB_ZPmI_H:
    case Opcode::AArch64_FSUB_ZPmI_S:  // Example bytecode - 00849965
    case Opcode::AArch64_FMUL_ZPmI_D:
    case Opcode::AArch64_FMUL_ZPmI_H:
    case Opcode::AArch64_FMUL_ZPmI_S:  // Example bytecode - 00809a65
    case Opcode::AArch64_FADD_ZPmI_D:  // Example bytecode - 0584d865
    case Opcode::AArch64_FADD_ZPmI_H:
    case Opcode::AArch64_FADD_ZPmI_S: {
      // Incorrect access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      // Extract FP constant imm
      aarch64_exactfpimm exactFp = operands[3].sysop.imm.exactfpimm;
      if (exactFp == AARCH64_EXACTFPIMM_HALF)
        operands[3].fp = 0.5;
      else if (exactFp == AARCH64_EXACTFPIMM_ONE)
        operands[3].fp = 1.0;
      else if (exactFp == AARCH64_EXACTFPIMM_TWO)
        operands[3].fp = 2.0;
      else if (exactFp == AARCH64_EXACTFPIMM_ZERO)
        operands[3].fp = 0.0;
      else
        assert(false && "Invalid FP immidate contant.");
      break;
    }
    case Opcode::AArch64_SMULH_ZPmZ_B:  // Example bytecode - 20001204
    case Opcode::AArch64_SMULH_ZPmZ_D:
    case Opcode::AArch64_SMULH_ZPmZ_H:
    case Opcode::AArch64_SMULH_ZPmZ_S:
    case Opcode::AArch64_SMIN_ZPmZ_B:
    case Opcode::AArch64_SMIN_ZPmZ_D:
    case Opcode::AArch64_SMIN_ZPmZ_H:
    case Opcode::AArch64_SMIN_ZPmZ_S:  // Example bytecode - 01008a04
    case Opcode::AArch64_SMAX_ZPmZ_B:
    case Opcode::AArch64_SMAX_ZPmZ_D:
    case Opcode::AArch64_SMAX_ZPmZ_H:
    case Opcode::AArch64_SMAX_ZPmZ_S:  // Example bytecode - 01008804
    case Opcode::AArch64_MUL_ZPmZ_B:   // Example bytecode - 40001004
    case Opcode::AArch64_MUL_ZPmZ_D:
    case Opcode::AArch64_MUL_ZPmZ_H:
    case Opcode::AArch64_MUL_ZPmZ_S:
    case Opcode::AArch64_FSUBR_ZPmZ_D:
    case Opcode::AArch64_FSUBR_ZPmZ_H:
    case Opcode::AArch64_FSUBR_ZPmZ_S:  // Example bytecode - 24808365
    case Opcode::AArch64_FSUB_ZPmZ_D:
    case Opcode::AArch64_FSUB_ZPmZ_H:
    case Opcode::AArch64_FSUB_ZPmZ_S:  // Example bytecode - 24808165
    case Opcode::AArch64_FMUL_ZPmZ_D:
    case Opcode::AArch64_FMUL_ZPmZ_H:
    case Opcode::AArch64_FMUL_ZPmZ_S:  // Example bytecode - 83808265
    case Opcode::AArch64_FDIV_ZPmZ_D:  // Example bytecode - 0184cd65
    case Opcode::AArch64_FDIV_ZPmZ_H:
    case Opcode::AArch64_FDIV_ZPmZ_S:
    case Opcode::AArch64_FDIVR_ZPmZ_D:  // Example bytecode - 0184cc65
    case Opcode::AArch64_FDIVR_ZPmZ_H:
    case Opcode::AArch64_FDIVR_ZPmZ_S:
    case Opcode::AArch64_FADDA_VPZ_D:
    case Opcode::AArch64_FADDA_VPZ_H:
    case Opcode::AArch64_FADDA_VPZ_S:  // Example bytecode - 01249865
    case Opcode::AArch64_FADD_ZPmZ_D:  // Example bytecode - 6480c065
    case Opcode::AArch64_FADD_ZPmZ_H:
    case Opcode::AArch64_FADD_ZPmZ_S:
    case Opcode::AArch64_FCADD_ZPmZ_D:  // Example bytecode - 2080c064
    case Opcode::AArch64_FCADD_ZPmZ_H:
    case Opcode::AArch64_FCADD_ZPmZ_S:
    case Opcode::AArch64_ADD_ZPmZ_B:  // Example bytecode - 00000004
    case Opcode::AArch64_ADD_ZPmZ_D:
    case Opcode::AArch64_ADD_ZPmZ_H:
    case Opcode::AArch64_ADD_ZPmZ_S:
    case Opcode::AArch64_EOR_ZPmZ_B:  // Example bytecode - 20001904
    case Opcode::AArch64_EOR_ZPmZ_D:
    case Opcode::AArch64_EOR_ZPmZ_H:
    case Opcode::AArch64_EOR_ZPmZ_S:
      // Incorrect access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    case Opcode::AArch64_FMOVXDHighr:  // Example bytecode - 4100af9e
      // FMOVXDHighr incorrectly flags destination as WRITE only
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      break;
    case Opcode::AArch64_FCVTNv4i32:  // Example bytecode - 0168614e
      // Wrong access type for destination operand
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_CPY_ZPzI_B:
    case Opcode::AArch64_CPY_ZPzI_D:
    case Opcode::AArch64_CPY_ZPzI_H:  // Example bytecode - 01215005
    case Opcode::AArch64_CPY_ZPzI_S: {
      // Imm value not correctly set
      std::string tmpOpStr(operandStr.substr(operandStr.find("#") + 1));
      auto value = std::stoi(tmpOpStr, 0, 16);
      // Ensure #imm is kept within the spec defined limits
      operands[2].imm = tmpOpStr.length() == 4 ? static_cast<int8_t>(value)
                                               : static_cast<int16_t>(value);
      break;
    }
    case Opcode::AArch64_ZERO_M: {
      // Operands often mangled from ZA tile overlap aliasing in decode.
      // Need to re-extract relevant tiles from operandStr
      operandCount = 0;
      size_t pos = operandStr.find("za", 0);
      while (pos != std::string::npos) {
        size_t pos_2 = operandStr.find(".", pos);
        if (pos_2 != std::string::npos) {
          char type = operandStr[pos_2 + 1];
          // Tile Number can only ever be 1 digit
          uint8_t tileNum = std::stoi(operandStr.substr((pos + 2), 1));
          switch (type) {
            case 'b':
              operands[operandCount].sme.tile = AARCH64_REG_ZAB0;
              break;
            case 'h':

              operands[operandCount].sme.tile =
                  static_cast<aarch64_reg>(AARCH64_REG_ZAH0 + tileNum);
              break;
            case 's':

              operands[operandCount].sme.tile =
                  static_cast<aarch64_reg>(AARCH64_REG_ZAS0 + tileNum);
              break;
            case 'd':

              operands[operandCount].sme.tile =
                  static_cast<aarch64_reg>(AARCH64_REG_ZAD0 + tileNum);
              break;
            case 'q':

              operands[operandCount].sme.tile =
                  static_cast<aarch64_reg>(AARCH64_REG_ZAQ0 + tileNum);
              break;
          }
        } else {
          operands[operandCount].sme.tile = AARCH64_REG_ZA;
        }
        operands[operandCount].type = AARCH64_OP_SME;
        operands[operandCount].access = CS_AC_WRITE;
        operandCount++;
        pos = operandStr.find("za", pos + 1);
      }
      break;
    }
  }
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding,
                                         uint8_t bytes)
    : id(AARCH64_INS_INVALID),
      opcode(Opcode::INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      groupCount(0),
      setsFlags(false),
      isAlias(false),
      operandCount(0) {
  assert(bytes <= sizeof(encoding));
  std::memcpy(encoding, invalidEncoding, bytes);
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng