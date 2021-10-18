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
      cc(insn.detail->arm64.cc - 1),
      setsFlags(insn.detail->arm64.update_flags),
      writeback(insn.detail->arm64.writeback),
      operandCount(insn.detail->arm64.op_count) {
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
  std::memcpy(operands, insn.detail->arm64.operands,
              sizeof(cs_arm64_op) * operandCount);

  // Fix some inaccuracies in the decoded metadata
  switch (opcode) {
    case Opcode::AArch64_BICv4i32:
      // BIC incorrectly flags destination as WRITE only
      operands[0].access = CS_AC_WRITE | CS_AC_READ;
      break;
    case Opcode::AArch64_ADDSWri:
      // adds incorrectly flags destination as READ
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_ADDVL_XXI:
      // lacking access specifiers for all operands
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_BICv8i8:
      // access specifier for last operand was missing
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_CASALW:
      [[fallthrough]];
    case Opcode::AArch64_CASALX:
      operandCount = 3;
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_CBNZW:
      [[fallthrough]];
    case Opcode::AArch64_CBNZX:
      [[fallthrough]];
    case Opcode::AArch64_CBZW:
      [[fallthrough]];
    case Opcode::AArch64_CBZX:
      // incorrectly adds implicit nzcv dependency
      implicitSourceCount = 0;
      break;
    case Opcode::AArch64_CMPGT_PPzZZ_B:
      [[fallthrough]];
    case Opcode::AArch64_CMPGT_PPzZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_CMPGT_PPzZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_CMPGT_PPzZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_CMPNE_PPzZI_S:
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      // Doesn't identify implicit NZCV destination
      implicitDestinationCount = 1;
      implicitDestinations[0] = ARM64_REG_NZCV;
      break;
    case Opcode::AArch64_CNTB_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_CNTH_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_CNTD_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_CNTW_XPiI: {
      // lacking access specifiers for destination
      operands[0].access = CS_AC_WRITE;
      if (operandStr.length() < 4) {
        operandCount = 2;
        operands[1].type = ARM64_OP_IMM;
        operands[1].imm = 1;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        operands[1].ext = ARM64_EXT_INVALID;
        operands[1].vector_index = -1;
      }
      break;
    }
    case Opcode::AArch64_DECD_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_DECB_XPiI:
      // lacking access specifiers for destination
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      break;
    case Opcode::AArch64_EOR_PPzPP: {
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_FMOVXDHighr:
      // FMOVXDHighr incorrectly flags destination as only WRITE
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      break;
    case Opcode::AArch64_FMOVSi:
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[1].type = ARM64_OP_IMM;
      break;
    case Opcode::AArch64_FNMLS_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FNMLS_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FADDA_VPZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FDIV_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMAD_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMAD_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FMLA_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMLA_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FMLS_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMLS_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FMSB_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMSB_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_MLA_ZPmZZ_B:
      [[fallthrough]];
    case Opcode::AArch64_MLA_ZPmZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_MLA_ZPmZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_MLA_ZPmZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SMAX_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SMIN_ZPmZ_S:
      // No defined access types
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    case Opcode::AArch64_MOVPRFX_ZPzZ_D:
      [[fallthrough]];
    case Opcode::AArch64_MOVPRFX_ZPzZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SUB_ZZZ_B:
      [[fallthrough]];
    case Opcode::AArch64_SUB_ZZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_SUB_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SUB_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_II_B:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_II_H:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_II_S:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_II_D:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_IR_B:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_IR_D:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_IR_H:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_IR_S:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RI_B:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RI_D:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RI_H:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RI_S:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RR_B:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RR_D:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RR_H:
      [[fallthrough]];
    case Opcode::AArch64_INDEX_RR_S:
      [[fallthrough]];
    case Opcode::AArch64_ADD_ZZZ_B:
      [[fallthrough]];
    case Opcode::AArch64_ADD_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_ADD_ZZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_ADD_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FADD_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FADD_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FSUB_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FSUB_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FMUL_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMUL_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FNEG_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FNEG_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SMINV_VPZ_S:
      [[fallthrough]];
    case Opcode::AArch64_UZP1_ZZZ_S:
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_FABS_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FABS_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FSQRT_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FSQRT_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FCVTZS_ZPmZ_DtoS:
      // No defined access types
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_FMUL_ZPmI_D:
      [[fallthrough]];
    case Opcode::AArch64_FMUL_ZPmI_S: {
      // No defined access types
      operandCount = 4;
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].type = ARM64_OP_FP;
      operands[3].access = CS_AC_READ;
      // Doesn't recognise immediate operands
      // Extract two possible values, 0.5 or 2.0
      if (operandStr.substr(operandStr.length() - 1, 1) == "5") {
        operands[3].fp = 0.5f;
      } else {
        operands[3].fp = 2.0f;
      }

      break;
    }
    case Opcode::AArch64_FADD_ZPmI_D:
      [[fallthrough]];
    case Opcode::AArch64_FADD_ZPmI_S:
      // No defined access types
      operandCount = 4;
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].type = ARM64_OP_FP;
      operands[3].access = CS_AC_READ;
      // Doesn't recognise immediate operands
      // Extract two possible values, 0.5 or 1.0
      if (operandStr.substr(operandStr.length() - 1, 1) == "5") {
        operands[3].fp = 0.5f;
      } else {
        operands[3].fp = 1.0f;
      }
      break;
    case Opcode::AArch64_FCMGT_PPzZ0_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMGT_PPzZ0_S: {
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_FDIVR_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FDIVR_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_AND_PPzPP:
      [[fallthrough]];
    case Opcode::AArch64_FADD_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMGE_PPzZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMGE_PPzZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FCMGE_PPzZ0_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMGE_PPzZ0_S:
      [[fallthrough]];
    case Opcode::AArch64_FCMGT_PPzZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMGT_PPzZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_FCMLE_PPzZ0_D:
      [[fallthrough]];
    case Opcode::AArch64_FCMLE_PPzZ0_S:
      [[fallthrough]];
    case Opcode::AArch64_FCMLT_PPzZ0_S:
      [[fallthrough]];
    case Opcode::AArch64_FMUL_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FMUL_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_MUL_ZPmZ_B:
      [[fallthrough]];
    case Opcode::AArch64_MUL_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_MUL_ZPmZ_H:
      [[fallthrough]];
    case Opcode::AArch64_MUL_ZPmZ_S:
      [[fallthrough]];
    case Opcode::AArch64_SEL_ZPZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_SEL_ZPZZ_S:
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    case Opcode::AArch64_FDUP_ZI_D:
      [[fallthrough]];
    case Opcode::AArch64_FDUP_ZI_S:
      [[fallthrough]];
    case Opcode::AArch64_PUNPKHI_PP:
      [[fallthrough]];
    case Opcode::AArch64_PUNPKLO_PP:
      [[fallthrough]];
    case Opcode::AArch64_RDVLI_XI:
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_INCB_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_INCD_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_INCH_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_INCW_XPiI: {
      // lacking access specifiers for destination
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      if (operandStr.length() < 4) {
        operandCount = 2;
        operands[1].type = ARM64_OP_IMM;
        operands[1].imm = 1;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        operands[1].ext = ARM64_EXT_INVALID;
        operands[1].vector_index = -1;
      }
      break;
    }
    case Opcode::AArch64_INCD_ZPiI:
      [[fallthrough]];
    case Opcode::AArch64_INCH_ZPiI:
      [[fallthrough]];
    case Opcode::AArch64_INCW_ZPiI: {
      // lacking access specifiers for destination
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      if (operandStr.length() < 6) {
        operandCount = 2;
        operands[1].type = ARM64_OP_IMM;
        operands[1].imm = 1;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        operands[1].ext = ARM64_EXT_INVALID;
        operands[1].vector_index = -1;
      }
      break;
    }
    case Opcode::AArch64_LD1i32:
      [[fallthrough]];
    case Opcode::AArch64_LD1i64:
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_GLD1D_SCALED_REAL:
      [[fallthrough]];
    case Opcode::AArch64_GLD1D_REAL: {
      // LD1D gather instruction doesn't correctly identify destination register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }
      operands[0].reg = static_cast<arm64_reg>(reg_enum);

      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      // LD1D gather instruction doesn't correctly identify memory operands
      operands[2].type = ARM64_OP_MEM;
      operands[2].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_GLD1SW_D_IMM_REAL:
      [[fallthrough]];
    case Opcode::AArch64_GLD1D_IMM_REAL: {
      // LD1D gather instruction doesn't correctly identify destination register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      // LD1D gather instruction doesn't correctly identify second Z reg as
      // memory operand
      operands[2].type = ARM64_OP_MEM;
      operands[2].access = CS_AC_READ;
      // LD1D gather instruction doesn't recognise memory-offset immediate
      // correctly
      if (operandStr[operandStr.length() - 3] != '.') {
        int64_t startPos = operandStr.find('#') + 1;
        int64_t immSize = (operandStr.length() - 1) - startPos;
        if (immSize == 1) {
          operands[2].mem.disp =
              std::stoi(operandStr.substr(startPos, immSize));
        } else {
          // double or tripple digit immediates are converted to hex, and so
          // require a different conversion to uint
          operands[2].mem.disp =
              std::stoul(operandStr.substr(startPos, immSize), nullptr, 16);
        }
      }
      break;
    }
    case Opcode::AArch64_LD1B:
      [[fallthrough]];
    case Opcode::AArch64_LD1D:
      [[fallthrough]];
    case Opcode::AArch64_LD1D_IMM_REAL:
      [[fallthrough]];
    case Opcode::AArch64_LD1RD_IMM:
      [[fallthrough]];
    case Opcode::AArch64_LD1RW_IMM:
      [[fallthrough]];
    case Opcode::AArch64_LD1H:
      [[fallthrough]];
    case Opcode::AArch64_LD1W:
      [[fallthrough]];
    case Opcode::AArch64_LD1W_IMM_REAL: {
      // LD1RW doesn't correctly identify destination register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_LD1Rv4h_POST:
      [[fallthrough]];
    case Opcode::AArch64_LD1Rv8h_POST:
      // Fix for exclusion of post_index immediate in disassembly
      operandCount = 3;
      operands[2].type = ARM64_OP_IMM;
      operands[2].access = CS_AC_READ;
      // For vector arrangment of 16-bit, post_index immediate is 2
      operands[2].imm = 2;
      break;
    case Opcode::AArch64_LD1Rv1d_POST:
      [[fallthrough]];
    case Opcode::AArch64_LD1Rv2d_POST:
      // Fix for exclusion of post_index immediate in disassembly
      operandCount = 3;
      operands[2].type = ARM64_OP_IMM;
      operands[2].access = CS_AC_READ;
      // For vector arrangment of 64-bit, post_index immediate is 8
      operands[2].imm = 8;
      break;
    case Opcode::AArch64_LD1Rv16b_POST:
      [[fallthrough]];
    case Opcode::AArch64_LD1Rv8b_POST:
      // Fix for exclusion of post_index immediate in disassembly
      operandCount = 3;
      operands[2].type = ARM64_OP_IMM;
      operands[2].access = CS_AC_READ;
      // For vector arrangment of 8-bit, post_index immediate is 1
      operands[2].imm = 1;
      break;
    case Opcode::AArch64_LD1Rv2s_POST:
      [[fallthrough]];
    case Opcode::AArch64_LD1Rv4s_POST:
      // Fix for exclusion of post_index immediate in disassembly
      operandCount = 3;
      operands[2].type = ARM64_OP_IMM;
      operands[2].access = CS_AC_READ;
      // For vector arrangment of 32-bit, post_index immediate is 4
      operands[2].imm = 4;
      break;
    case Opcode::AArch64_LD1Twov16b:
      [[fallthrough]];
    case Opcode::AArch64_LD1Twov16b_POST:
      // Fix incorrect access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_LDADDLW:
      [[fallthrough]];
    case Opcode::AArch64_LDADDW:
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_LD2Twov4s_POST:
      // Fixing wrong access flag for offset register operand
      if (operandCount == 4) {
        operands[3].access = CS_AC_READ;
      }
      break;
    case Opcode::AArch64_LDR_PXI:
      [[fallthrough]];
    case Opcode::AArch64_LDR_ZXI:
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_LSL_ZZI_S:
      // No defined access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      // No instruction id assigned
      id = ARM64_INS_LSL;
      break;
    case Opcode::AArch64_MOVNWi:
      [[fallthrough]];
    case Opcode::AArch64_MOVNXi:
      [[fallthrough]];
    case Opcode::AArch64_MOVZWi:
      [[fallthrough]];
    case Opcode::AArch64_MOVZXi:
      // MOVZ incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_MOVPRFX_ZZ:
      // Assign operand access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_MRS:
      // MRS incorrectly flags source/destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      // MRS incorrectly tags ARM64_OP_REG_MRS as ARM64_OP_SYS
      operands[1].type = ARM64_OP_REG_MRS;
      break;
    case Opcode::AArch64_MSR:
      // MSR incorrectly flags source/destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      // MSR incorrectly tags ARM64_OP_REG_MSR as ARM64_OP_SYS
      operands[0].type = ARM64_OP_REG_MSR;
      break;
    case Opcode::AArch64_PTEST_PP: {
      // PTEST doesn't label access types for operands
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      // Doesn't identify implicit NZCV destination
      implicitDestinationCount = 1;
      implicitDestinations[0] = ARM64_REG_NZCV;
      break;
    }
    case Opcode::AArch64_PTRUE_B:
      [[fallthrough]];
    case Opcode::AArch64_PTRUE_H:
      [[fallthrough]];
    case Opcode::AArch64_PTRUE_D:
      [[fallthrough]];
    case Opcode::AArch64_PTRUE_S:
      // PTRUE doesn't label access
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_RET:
      // If no register supplied to RET, default to x30 (LR)
      if (operandCount == 0) {
        operandCount = 1;
        operands[0].type = ARM64_OP_REG;
        operands[0].reg = ARM64_REG_LR;
        operands[0].access = CS_AC_READ;
      }
      groupCount = 1;
      groups[0] = CS_GRP_JUMP;
      break;
    case Opcode::AArch64_REV_ZZ_B:
      [[fallthrough]];
    case Opcode::AArch64_REV_ZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_REV_ZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_REV_ZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_REV_PP_B:
      [[fallthrough]];
    case Opcode::AArch64_REV_PP_D:
      [[fallthrough]];
    case Opcode::AArch64_REV_PP_H:
      [[fallthrough]];
    case Opcode::AArch64_REV_PP_S: {
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_SST1B_D:
      [[fallthrough]];
    case Opcode::AArch64_SST1D:
      [[fallthrough]];
    case Opcode::AArch64_SST1D_SCALED: {
      // ST1W doesn't correctly identify first source register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      // SST1D{_SCALED} gather instruction doesn't correctly identify memory
      // operands
      operands[2].type = ARM64_OP_MEM;
      operands[2].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_ST1B:
      [[fallthrough]];
    case Opcode::AArch64_ST1D:
      [[fallthrough]];
    case Opcode::AArch64_ST1D_IMM:
      [[fallthrough]];
    case Opcode::AArch64_ST1W_IMM: {
      // ST1W doesn't correctly identify first source register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_ST1W:
      [[fallthrough]];
    case Opcode::AArch64_ST1W_D: {
      // ST1W doesn't correctly identify first source register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      operands[3].access = CS_AC_READ;
      break;
    }
    case Opcode::AArch64_SST1D_IMM:
      [[fallthrough]];
    case Opcode::AArch64_SST1W_D_IMM:
      [[fallthrough]];
    case Opcode::AArch64_SST1W_IMM: {
      // ST1W scatter instruction doesn't correctly identify first source
      // register
      uint16_t reg_enum = ARM64_REG_Z0;
      // Single or double digit Z register identifier
      if (operandStr[3] == '.') {
        reg_enum += std::stoi(operandStr.substr(2, 1));
      } else {
        reg_enum += std::stoi(operandStr.substr(2, 2));
      }

      operands[0].reg = static_cast<arm64_reg>(reg_enum);
      // No defined access types
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
      // ST1W scatter instruction doesn't correctly identify second Z reg as
      // memory operand
      operands[2].type = ARM64_OP_MEM;
      operands[2].access = CS_AC_READ;
      // ST1W scatter instruction doesn't recognise memory-offset immediate
      // correctly
      if (operandStr[operandStr.length() - 3] != '.') {
        int64_t startPos = operandStr.find('#') + 1;
        int64_t immSize = (operandStr.length() - 1) - startPos;
        if (immSize == 1) {
          operands[2].mem.disp =
              std::stoi(operandStr.substr(startPos, immSize));
        } else {
          // double or tripple digit immediates are converted to hex, and so
          // require a different conversion to uint
          operands[2].mem.disp =
              std::stoul(operandStr.substr(startPos, immSize), nullptr, 16);
        }
      }
      break;
    }
    case Opcode::AArch64_ST1i8_POST:
      [[fallthrough]];
    case Opcode::AArch64_ST1i16_POST:
      [[fallthrough]];
    case Opcode::AArch64_ST1i32_POST:
      [[fallthrough]];
    case Opcode::AArch64_ST1i64_POST:
      // fixing incorrect access type for register offset
      if (operandCount == 3) {
        operands[2].access = CS_AC_READ;
      }
      break;
    case Opcode::AArch64_ST1Twov16b:
      // ST1 incorrectly flags read and write
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_ST2Twov4s_POST:
      // ST2 post incorrectly flags read and write
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ | CS_AC_WRITE;
      // Another incorrect acess flag for register offset operand
      if (operandCount == 4) {
        operands[3].access = CS_AC_READ;
      }
      break;
    case Opcode::AArch64_STR_PXI:
      [[fallthrough]];
    case Opcode::AArch64_STR_ZXI:
      operands[0].access = CS_AC_READ;
      operands[1].access = CS_AC_READ;
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
    case Opcode::AArch64_SYSxt:
      // No defined metadata.id for SYS instructions
      id = ARM64_INS_SYS;
      break;
    case Opcode::AArch64_UBFMWri:
      [[fallthrough]];
    case Opcode::AArch64_UBFMXri:
      // UBFM incorrectly flags destination as READ | WRITE
      operands[0].access = CS_AC_WRITE;
      break;
    case Opcode::AArch64_UQDECB_WPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECB_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECD_WPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECD_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECH_WPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECH_XPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECW_WPiI:
      [[fallthrough]];
    case Opcode::AArch64_UQDECW_XPiI:
      // UQDEC lacks access types
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      if (operandCount == 1) {
        operandCount = 2;
        operands[1].type = ARM64_OP_IMM;
        operands[1].imm = 1;
      }
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_UUNPKHI_ZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_UUNPKHI_ZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_UUNPKHI_ZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_UUNPKLO_ZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_UUNPKLO_ZZ_H:
      [[fallthrough]];
    case Opcode::AArch64_UUNPKLO_ZZ_S:
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      break;
    case Opcode::AArch64_WHILELO_PXX_B:
      [[fallthrough]];
    case Opcode::AArch64_WHILELO_PXX_D:
      [[fallthrough]];
    case Opcode::AArch64_WHILELO_PXX_H:
      [[fallthrough]];
    case Opcode::AArch64_WHILELO_PXX_S:
      // WHILELO doesn't label access or vector specifiers
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      // Doesn't identify implicit NZCV destination
      implicitDestinationCount = 1;
      implicitDestinations[0] = ARM64_REG_NZCV;
      break;
    case Opcode::AArch64_XTNv16i8:
    case Opcode::AArch64_XTNv4i32:
    case Opcode::AArch64_XTNv8i16:
      // XTN2 incorrectly flags destination as only WRITE
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      break;
    case Opcode::AArch64_ZIP1_PPP_B:
      [[fallthrough]];
    case Opcode::AArch64_ZIP1_PPP_D:
      [[fallthrough]];
    case Opcode::AArch64_ZIP1_PPP_H:
      [[fallthrough]];
    case Opcode::AArch64_ZIP1_PPP_S:
      [[fallthrough]];
    case Opcode::AArch64_ZIP1_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_ZIP1_ZZZ_D:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_PPP_B:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_PPP_D:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_PPP_H:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_PPP_S:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_ZZZ_S:
      [[fallthrough]];
    case Opcode::AArch64_ZIP2_ZZZ_D:
      // ZIP lacks access types
      operands[0].access = CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
    case Opcode::AArch64_SXTW_ZPmZ_D:
      [[fallthrough]];
    case Opcode::AArch64_FCVT_ZPmZ_DtoS:
      [[fallthrough]];
    case Opcode::AArch64_FCVT_ZPmZ_StoD:
      [[fallthrough]];
    case Opcode::AArch64_SCVTF_ZPmZ_DtoS:
      [[fallthrough]];
    case Opcode::AArch64_SCVTF_ZPmZ_StoD:
      [[fallthrough]];
    case Opcode::AArch64_SCVTF_ZPmZ_StoS:
      [[fallthrough]];
    case Opcode::AArch64_SCVTF_ZPmZ_DtoD:
      // Need to see if Destination vector elements are active
      operands[0].access = CS_AC_READ | CS_AC_WRITE;
      operands[1].access = CS_AC_READ;
      operands[2].access = CS_AC_READ;
      break;
  }

  revertAliasing();
}

InstructionMetadata::InstructionMetadata(const uint8_t* invalidEncoding,
                                         uint8_t bytes)
    : id(ARM64_INS_INVALID),
      opcode(Opcode::AArch64_INSTRUCTION_LIST_END),
      implicitSourceCount(0),
      implicitDestinationCount(0),
      groupCount(0),
      setsFlags(false),
      writeback(false),
      operandCount(0) {
  assert(bytes <= sizeof(encoding));
  std::memcpy(encoding, invalidEncoding, bytes);
  mnemonic[0] = '\0';
  operandStr[0] = '\0';
}

void InstructionMetadata::revertAliasing() {
  // Check mnemonics known to be aliases and see if their opcode matches
  // something else
  switch (id) {
    case ARM64_INS_ASR:
      if (opcode == Opcode::AArch64_ASRVWr ||
          opcode == Opcode::AArch64_ASRVXr) {
        // asr rd, rn, rm; alias for: asrv rd, rn, rm
        return;
      }
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
      if (opcode == Opcode::AArch64_BFMWri) {
        // bfi wd, wn, #lsb, #width; alias for
        // bfm wd, wn, #(-lsb MOD 32), #(width - 1)
        operands[2].imm = static_cast<uint32_t>(-operands[2].imm) % 32;
        operands[3].imm = operands[3].imm - 1;
        return;
      }
      if (opcode == Opcode::AArch64_BFMXri) {
        // bfi xd, xn, #lsb, #width; alias for
        // bfm xd, xn, #(-lsb MOD 64), #(width - 1)
        operands[2].imm = static_cast<uint32_t>(-operands[2].imm) % 64;
        operands[3].imm = operands[3].imm - 1;
        return;
      }
      return aliasNYI();
    case ARM64_INS_BFXIL:
      if (opcode == Opcode::AArch64_BFMWri ||
          opcode == Opcode::AArch64_BFMXri) {
        // bfxil rd, rn, #lsb, #width; alias for
        // bfm rd, rn, #lsb, #(lsb + width - 1)
        operands[3].imm = operands[2].imm + operands[3].imm - 1;
        return;
      }
      return aliasNYI();
    case ARM64_INS_CINC:
      if (opcode == Opcode::AArch64_CSINCWr ||
          opcode == Opcode::AArch64_CSINCXr) {
        // cinc rd, rn, cc; alias for: csinc rd, rn, rn, invert(cc)
        operandCount = 3;

        operands[2].type = ARM64_OP_REG;
        operands[2].access = CS_AC_READ;
        operands[2].reg = operands[1].reg;

        cc ^= 1;  // invert lowest bit to negate cc
        return;
      }
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
          opcode == Opcode::AArch64_SUBSWrx ||
          opcode == Opcode::AArch64_SUBSXri ||
          opcode == Opcode::AArch64_SUBSXrs ||
          opcode == Opcode::AArch64_SUBSXrx ||
          opcode == Opcode::AArch64_SUBSXrx64) {
        operandCount = 3;
        operands[2] = operands[1];

        operands[1] = operands[0];
        operands[1].access = CS_AC_READ;

        operands[0].type = ARM64_OP_REG;
        operands[0].access = CS_AC_WRITE;

        if (opcode == Opcode::AArch64_SUBSWri ||
            opcode == Opcode::AArch64_SUBSWrs ||
            opcode == Opcode::AArch64_SUBSWrx) {
          operands[0].reg = ARM64_REG_WZR;
        } else {
          operands[0].reg = ARM64_REG_XZR;
        }
        return;
      }
      return aliasNYI();
    case ARM64_INS_CNEG:
      if (opcode == Opcode::AArch64_CSNEGWr ||
          opcode == Opcode::AArch64_CSNEGXr) {
        // cneg rd, rn, cc; alias for: csneg rd, rn, rn, invert(cc)
        operandCount = 3;
        operands[2] = operands[1];
        cc ^= 1;  // invert lowest bit to negate cc
        return;
      }
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
      if (opcode == Opcode::AArch64_CSINVWr ||
          opcode == Opcode::AArch64_CSINVXr) {
        // csetm rd, cc; alias for: csinv rd, zr, zr, invert(cc)
        operandCount = 3;

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;

        operands[2].type = ARM64_OP_REG;
        operands[2].access = CS_AC_READ;

        if (opcode == Opcode::AArch64_CSINVWr) {
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
          opcode == Opcode::AArch64_LSLVXr ||
          opcode == Opcode::AArch64_LSL_ZZI_S) {
        return;
      }
      return aliasNYI();
    case ARM64_INS_LSR:
      if (opcode == Opcode::AArch64_LSRVWr ||
          opcode == Opcode::AArch64_LSRVXr) {
        // lsr rd, rn, rm; alias for lsrv rd, rn, rm
        return;
      }
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
      if (opcode == Opcode::AArch64_MSUBXrrr) {
        // mneg xd, xn, xm; alias for msub xd, xn, xm, xzr
        operandCount = 4;
        operands[3].type = ARM64_OP_REG;
        operands[3].access = CS_AC_READ;
        operands[3].reg = ARM64_REG_XZR;
        return;
      }
      if (opcode == Opcode::AArch64_MSUBWrrr) {
        // mneg wd, wn, wm; alias for msub wd, wn, wm, wzr
        operandCount = 4;
        operands[3].type = ARM64_OP_REG;
        operands[3].access = CS_AC_READ;
        operands[3].reg = ARM64_REG_WZR;
        return;
      }
      return aliasNYI();
    case ARM64_INS_MOV:
      if (opcode == Opcode::AArch64_ADDXri ||
          opcode == Opcode::AArch64_ADDWri) {
        // mov to/from sp; alias for: add <sp|rd>, <rn|sp>, #0
        operandCount = 3;
        operands[2].type = ARM64_OP_IMM;
        operands[2].imm = 0;
        operands[2].access = CS_AC_READ;
        operands[2].shift.type = ARM64_SFT_INVALID;
        operands[2].vas = ARM64_VAS_INVALID;
        operands[2].vector_index = -1;
        return;
      }
      if (opcode == Opcode::AArch64_CPYi8 || opcode == Opcode::AArch64_CPYi16 ||
          opcode == Opcode::AArch64_CPYi32 ||
          opcode == Opcode::AArch64_CPYi64) {
        // mov vd, Vn.T[index]; alias for dup vd, Vn.T[index]
        return;
      }
      if (opcode == Opcode::AArch64_DUPM_ZI ||
          opcode == Opcode::AArch64_DUP_ZI_B ||
          opcode == Opcode::AArch64_DUP_ZI_D ||
          opcode == Opcode::AArch64_DUP_ZI_H ||
          opcode == Opcode::AArch64_DUP_ZI_S) {
        // mov Zd.T, #imm; alias for dupm Zd.T, #imm
        // or
        // mov Zd.T, #imm{, shift}; alias for dup Zd.T, #imm{, shift}
        operandCount = 2;
        operands[0].access = CS_AC_WRITE;
        operands[1].type = ARM64_OP_IMM;
        operands[1].access = CS_AC_READ;

        uint8_t start = operandStr[6] == '#' ? 7 : 8;

        if (opcode == Opcode::AArch64_DUPM_ZI) {
          char specifier = operandStr[start - 4];
          switch (specifier) {
            case 'b':
              operands[0].vas = ARM64_VAS_1B;
              break;
            case 'h':
              operands[0].vas = ARM64_VAS_1H;
              break;
            case 's':
              operands[0].vas = ARM64_VAS_1S;
              break;
            case 'd':
              operands[0].vas = ARM64_VAS_1D;
              break;

            default:
              break;
          }
        }

        bool hex = false;
        if (operandStr[start + 1] == 'x') {
          hex = true;
          start += 2;
        }

        uint8_t end = start + 1;
        while (true) {
          if (operandStr[end] < '0') {
            break;
          }
          end++;
        }

        std::string sub = operandStr.substr(start, end);
        if (hex) {
          operands[1].imm = std::stoul(sub, 0, 16);
        } else {
          operands[1].imm = stoi(sub);
        }

        return;
      }
      if (opcode == Opcode::AArch64_DUP_ZR_S ||
          opcode == Opcode::AArch64_DUP_ZR_D) {
        // mov Zd.T, <rn|sp>; alias for dup Zd.T, <rn|sp>
        operands[0].access = CS_AC_WRITE;
        operands[0].vas = ARM64_VAS_1S;
        operands[1].access = CS_AC_READ;
        return;
      }
      if (opcode == Opcode::AArch64_DUP_ZZI_S ||
          opcode == Opcode::AArch64_DUP_ZZI_D) {
        // mov Zd.T, Vn; alias for dup Zd.T, Zn.T[0]
        operandCount = 2;
        operands[0].access = CS_AC_WRITE;
        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;

        uint8_t start = operandStr[2] == '.' ? 7 : 8;
        uint8_t end = operandStr.length() - start;

        // ARM64_REG_Z0 == 245
        operands[1].reg =
            static_cast<arm64_reg>(245 + stoi(operandStr.substr(start, end)));
        operands[1].vector_index = 0;
        return;
      }
      if (opcode == Opcode::AArch64_INSvi32lane ||
          opcode == Opcode::AArch64_INSvi64lane) {
        // mov vd.T[index1], vn.T[index2]; alias for ins vd.T[index1],
        // vn.T[index2]
        return;
      }
      if (opcode == Opcode::AArch64_ORRWri ||
          opcode == Opcode::AArch64_ORRWrs ||
          opcode == Opcode::AArch64_ORRXri ||
          opcode == Opcode::AArch64_ORRXrs) {
        // mov rd, rn; alias for: orr rd, zr, rn
        operandCount = 3;
        operands[2] = operands[1];

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        if (opcode == Opcode::AArch64_ORRWri ||
            opcode == Opcode::AArch64_ORRWrs) {
          operands[1].reg = ARM64_REG_WZR;
        } else {
          operands[1].reg = ARM64_REG_XZR;
        }
        return;
      }
      if (opcode == Opcode::AArch64_ORR_PPzPP) {
        // mov Pd.b, Pn.b; alias for: orr Pd.b, Pn/z, Pn.b, Pn.b
        operandCount = 4;
        operands[0].access = CS_AC_WRITE;
        operands[0].vas = ARM64_VAS_1B;
        operands[1].access = CS_AC_READ;
        operands[1].vas = ARM64_VAS_1B;
        operands[2] = operands[1];
        operands[3] = operands[1];
        return;
      }
      if (opcode == Opcode::AArch64_ORR_ZZZ) {
        // mov Zd.d, Zn.d; alias for: orr Zd.d, Zn.d, Zn.d
        operandCount = 3;
        operands[0].access = CS_AC_WRITE;
        operands[1].access = CS_AC_READ;
        operands[2] = operands[1];
        return;
      }
      if (opcode == Opcode::AArch64_ORRv16i8) {
        // mov Vd.16b, Vn.16b; alias for: orr Vd.16b, Vn.16b, Vn.16b
        operandCount = 3;
        operands[2] = operands[1];
        return;
      }
      if (opcode == Opcode::AArch64_SEL_ZPZZ_S ||
          opcode == Opcode::AArch64_SEL_ZPZZ_D) {
        // mov Zd.T, Pg/M, Zn.T; alias for: sel Zd.T, Pg, Zn.T, Zd.T
        if (mnemonic[0] == 'm') {
          // SEL instructions id sometimes set as ARM64_INS_MOV even if aliasing
          // hasn't occured so double check mnemoic is MOV alias
          operandCount = 4;
          operands[3] = operands[0];
          operands[3].access = CS_AC_READ;
        }
        return;
      }
      if (opcode == Opcode::AArch64_UMOVvi8 ||
          opcode == Opcode::AArch64_UMOVvi16 ||
          opcode == Opcode::AArch64_UMOVvi32 ||
          opcode == Opcode::AArch64_UMOVvi64) {
        // mov rd, Vn.T[index]; alias for umov rd, Vn.T[index]
        return;
      }
      if (opcode == Opcode::AArch64_MOVZWi ||
          opcode == Opcode::AArch64_MOVZXi) {
        // mov rd, #0; alias for: movz rd, #0{, shift #0}
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_LSL, 0};
        return;
      }
      if (opcode == Opcode::AArch64_MOVNWi ||
          opcode == Opcode::AArch64_MOVNXi) {
        // mov rd, #amount; alias for: movn rd, #amount{, shift #0}
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_LSL, 0};
        operands[1].imm = ~(operands[1].imm);
        return;
      }
      if (opcode == Opcode::AArch64_INSvi8gpr ||
          opcode == Opcode::AArch64_INSvi16gpr ||
          opcode == Opcode::AArch64_INSvi32gpr ||
          opcode == Opcode::AArch64_INSvi64gpr) {
        // mov vd.ts[index], rn; alias for: ins vd.ts[index], rn
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
      if (opcode == Opcode::AArch64_MUL_ZPmZ_B ||
          opcode == Opcode::AArch64_MUL_ZPmZ_D ||
          opcode == Opcode::AArch64_MUL_ZPmZ_H ||
          opcode == Opcode::AArch64_MUL_ZPmZ_S) {
        return;
      }
      return aliasNYI();
    case ARM64_INS_MVN:
      if (opcode == Opcode::AArch64_ORNWrs ||
          opcode == Opcode::AArch64_ORNXrs) {
        // mvn rd, rn; alias for: orn rd, zr, rn
        operandCount = 3;
        operands[2] = operands[1];

        operands[1].type = ARM64_OP_REG;
        operands[1].access = CS_AC_READ;
        operands[1].shift = {ARM64_SFT_INVALID, 0};
        if (opcode == Opcode::AArch64_ORNWrs) {
          operands[1].reg = ARM64_REG_WZR;
        } else {
          operands[1].reg = ARM64_REG_XZR;
        }
        return;
      }
      if (opcode == Opcode::AArch64_NOTv16i8 ||
          opcode == Opcode::AArch64_NOTv8i8) {
        // mvn vd.t, vn.t; alias for : not vd.t, vn.t
        // Blank entry was for a legitimate alias, however operands were
        // identical so nothing to alter between the instructions.
        return;
      }
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
      if (opcode == Opcode::AArch64_SUBSWrs ||
          opcode == Opcode::AArch64_SUBSXrs) {
        // negs rd, rm{, shift #amount}; alias for:
        //  subs rd, zr, rm{, shift #amount}
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
    case ARM64_INS_NGC:
      return aliasNYI();
    case ARM64_INS_NGCS:
      return aliasNYI();
    case ARM64_INS_NOT:
      if (opcode == Opcode::AArch64_EOR_PPzPP) {
        // not pd.b, pg/z, pn.b; alisas for: eor pd.b, pg/z, pn.b, pg.b
        operandCount = 4;
        operands[0].access = CS_AC_WRITE;
        operands[1].access = CS_AC_READ;
        operands[2].access = CS_AC_READ;
        operands[3] = operands[1];
        return;
      }
      return aliasNYI();
    case ARM64_INS_REV64:
      return aliasNYI();
    case ARM64_INS_ROR:
      return aliasNYI();
    case ARM64_INS_SBFIZ:
      if (opcode == Opcode::AArch64_SBFMWri ||
          opcode == Opcode::AArch64_SBFMXri) {
        operands[3].imm -= 1;

        uint8_t highestBit = 63;
        if (opcode == Opcode::AArch64_SBFMWri) {
          highestBit = 31;
        }

        operands[2].imm = (-operands[2].imm) & highestBit;
        return;
      }
      return aliasNYI();
    case ARM64_INS_SBFX:
      if (opcode == Opcode::AArch64_SBFMWri ||
          opcode == Opcode::AArch64_SBFMXri) {
        // sbfx rd, rn, #lsb, #width; alias for
        // sbfm rd, rn, #lsb, #(lsb + width - 1)
        operands[3].imm = operands[2].imm + operands[3].imm - 1;
        return;
      }
      return aliasNYI();
    case ARM64_INS_SMNEGL:
      return aliasNYI();
    case ARM64_INS_SMULL:
      if (opcode == Opcode::AArch64_SMADDLrrr) {
        operandCount = 4;
        operands[3].type = ARM64_OP_REG;
        operands[3].access = CS_AC_READ;
        operands[3].reg = ARM64_REG_XZR;
        return;
      }
      return aliasNYI();
    case ARM64_INS_SXTB:
      // sxtb rd, rn; alias for: sbfm rd, rn, #0, #7
      if (opcode == Opcode::AArch64_SBFMWri ||
          opcode == Opcode::AArch64_SBFMXri) {
        operandCount = 4;

        operands[2].type = ARM64_OP_IMM;
        operands[2].access = CS_AC_READ;
        operands[2].imm = 0;

        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;
        operands[3].imm = 7;
        return;
      }
      return aliasNYI();
    case ARM64_INS_SXTH:
      // sxth rd, rn; alias for: sbfm rd, rn, #0, #15
      if (opcode == Opcode::AArch64_SBFMWri ||
          opcode == Opcode::AArch64_SBFMXri) {
        operandCount = 4;

        operands[2].type = ARM64_OP_IMM;
        operands[2].access = CS_AC_READ;
        operands[2].imm = 0;

        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;
        operands[3].imm = 15;
        return;
      }
      return aliasNYI();
    case ARM64_INS_SXTW:
      // sxtw rd, rn; alias for: sbfm rd, rn, #0, #31
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
      if (opcode == Opcode::AArch64_SXTW_ZPmZ_D) {
        return;
      }
      return aliasNYI();
    case ARM64_INS_SYS: {
      // Extract IC/DC/AT/TLBI operation
      if (std::string(mnemonic) == "dc") {
        if (operandStr.substr(0, 3) == "zva") {
          id = ARM64_INS_DC;
          operandCount = 3;
          operands[1] = operands[0];
          operands[1].access = CS_AC_READ;
          operands[0].type = ARM64_OP_SYS;
          operands[0].sys = ARM64_DC_ZVA;
          operands[2].type = ARM64_OP_REG_MRS;
          operands[2].access = CS_AC_READ;
          operands[2].imm = ARM64_SYSREG_DCZID_EL0;
          return;
        }
      }
      return aliasNYI();
    }
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
      if (opcode == Opcode::AArch64_UBFMWri ||
          opcode == Opcode::AArch64_UBFMXri) {
        // ubfx rd, rn, #lsb, #width; alias for
        // ubfm rd, rn, #lsb, #(lsb + width - 1)
        operands[3].imm = operands[2].imm + operands[3].imm - 1;
        return;
      }
      return aliasNYI();
    case ARM64_INS_UMNEGL:
      return aliasNYI();
    case ARM64_INS_UMULL:
      // umull xd, wn, wm; alias for: umaddl xd, wn, wm, xzr
      if (opcode == Opcode::AArch64_UMADDLrrr) {
        operandCount = 4;
        operands[3].type = ARM64_OP_REG;
        operands[3].access = CS_AC_READ;
        operands[3].reg = ARM64_REG_XZR;
        return;
      }
      return aliasNYI();
    case ARM64_INS_UXTB:
      // uxtb wd, wn; alias for: ubfm wd, wn, #0, #7
      if (opcode == Opcode::AArch64_UBFMWri) {
        operandCount = 4;
        operands[2].type = ARM64_OP_IMM;
        operands[2].access = CS_AC_READ;
        operands[2].imm = 0;
        operands[3].type = ARM64_OP_IMM;
        operands[3].access = CS_AC_READ;
        operands[3].imm = 7;
        return;
      }
      return aliasNYI();
    case ARM64_INS_UXTH:
      return aliasNYI();
  }
}

void InstructionMetadata::aliasNYI() { id = ARM64_INS_INVALID; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng