#include "InstructionMetadata.hh"

#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {
namespace arch {
namespace aarch64 {

/********************
 * HELPER FUNCTIONS
 *******************/

// Extract bit `start` of `value`
constexpr bool bit(uint32_t value, uint8_t start) {
  return (value >> start) & 1;
}

// Extract bits `start` to `start+width` of `value`
constexpr uint32_t bits(uint32_t value, uint8_t start, uint8_t width) {
  return ((value >> start) & ((1 << width) - 1));
}

// Generate a NZCV register identifier
constexpr Register nzcvReg() { return {RegisterType::NZCV, 0}; }

// Sign-extend a bitstring of length `currentLength`
constexpr int32_t signExtend(uint32_t value, int currentLength) {
  uint32_t mask = (0xFFFFFFFF) << currentLength;
  bool negative = bit(value, currentLength - 1);
  return static_cast<int32_t>(value) | (negative ? mask : 0);
}

/** Parses the Capstone `aarch64_reg` value to generate an architectural
 * register representation.
 *
 * WARNING: this conversion is FRAGILE, and relies on the structure of the
 * `aarch64_reg` enum. Updates to the Capstone library version may cause this to
 * break.
 * TODO: Add multi-register enum decoding.
 * */
Register csRegToRegister(aarch64_reg reg) {
  // Do not need check for AARCH64_REG_Vn as in Capstone, they are aliased as Qn
  // (full vector) or Dn (half vector).
  // As D and Q registers are also of type RegisterType::VECTOR, the outcome
  // will be the same

  // Assert that reg is not a SME tile as these should be passed to
  // `getZARowVectors()`
  assert(reg != AARCH64_REG_ZA);
  assert(!(AARCH64_REG_ZAB0 <= reg && reg <= AARCH64_REG_ZAS3));

  // AARCH64_REG_ZT0 is a fixed with Table register, reading from the table
  // register file.
  if (reg == AARCH64_REG_ZT0) {
    return {RegisterType::TABLE, 0};
  }

  // AARCH64_REG_Z0 -> +31 are scalable vector registers (Z) registers, reading
  // from the vector file
  if (AARCH64_REG_Z0 <= reg && reg <= AARCH64_REG_Z31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_Z0)};
  }

  // AARCH64_REG_X0 -> +28 are 64-bit (X) registers, reading from the general
  // file. Excludes #29 (FP) and #30 (LR)
  if (AARCH64_REG_X0 <= reg && reg <= AARCH64_REG_X28) {
    return {RegisterType::GENERAL, static_cast<uint16_t>(reg - AARCH64_REG_X0)};
  }

  // AARCH64_REG_W0 -> +30 are 32-bit (W) registers, reading from the general
  // file. Excludes #31 (WZR/WSP).
  if (AARCH64_REG_W0 <= reg && reg <= AARCH64_REG_W30) {
    return {RegisterType::GENERAL, static_cast<uint16_t>(reg - AARCH64_REG_W0)};
  }

  // AARCH64_REG_Q0 -> +31 are 128-bit registers representing scalar access
  // specifiers on the vector registers
  if (AARCH64_REG_Q0 <= reg && reg <= AARCH64_REG_Q31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_Q0)};
  }

  // AARCH64_REG_D0 -> +31 are 64-bit registers representing scalar access
  // specifiers on the vector registers
  if (AARCH64_REG_D0 <= reg && reg <= AARCH64_REG_D31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_D0)};
  }

  // AARCH64_REG_S0 -> +31 are 32-bit registers representing scalar access
  // specifiers on the vector registers
  if (AARCH64_REG_S0 <= reg && reg <= AARCH64_REG_S31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_S0)};
  }

  // AARCH64_REG_H0 -> +31 are 16-bit registers representing scalar access
  // specifiers on the vector registers
  if (AARCH64_REG_H0 <= reg && reg <= AARCH64_REG_H31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_H0)};
  }

  // AARCH64_REG_B0 -> +31 are 8-bit registers representing scalar access
  // specifiers on the vector registers
  if (AARCH64_REG_B0 <= reg && reg <= AARCH64_REG_B31) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - AARCH64_REG_B0)};
  }

  // AARCH64_REG_P0 -> +15 are 256-bit (P) "predicate-as-mask" registers.
  // Excludes #16 (FFR).
  // AARCH64_REG_PN0 -> +15 are 256-bit (PN) "predicate-as-counter" registers.
  if (AARCH64_REG_P0 <= reg && reg <= AARCH64_REG_PN15) {
    return {RegisterType::PREDICATE,
            static_cast<uint16_t>(static_cast<uint16_t>(reg - AARCH64_REG_P0) %
                                  16u)};
  }

  // AARCH64_REG_WZR and _XZR are zero registers, and don't read
  if (reg == AARCH64_REG_WZR || reg == AARCH64_REG_XZR) {
    return RegisterType::ZERO_REGISTER;
  }

  // AARCH64_REG_SP and _WSP are stack pointer registers, stored in r31 of the
  // general file
  if (reg == AARCH64_REG_SP || reg == AARCH64_REG_WSP) {
    return {RegisterType::GENERAL, 31};
  }

  // AARCH64_REG_NZCV is the condition flags register
  if (reg == AARCH64_REG_NZCV) {
    return {RegisterType::NZCV, 0};
  }
  // AARCH64_REG_X29 is the frame pointer, stored in r29 of the general file
  if (reg == AARCH64_REG_X29) {
    return {RegisterType::GENERAL, 29};
  }
  // AARCH64_REG_X30 is the link register, stored in r30 of the general file
  if (reg == AARCH64_REG_X30) {
    return {RegisterType::GENERAL, 30};
  }

  if (reg == AARCH64_REG_FFR) {
    return {RegisterType::PREDICATE, 16};
  }

  assert(false && "Decoding failed due to unknown register identifier");
  return {std::numeric_limits<uint8_t>::max(),
          std::numeric_limits<uint16_t>::max()};
}

/** Returns a full set of rows from the ZA matrix register that make up the
 * supplied SME tile register. */
std::vector<Register> getZARowVectors(aarch64_reg reg,
                                      const uint64_t SVL_bits) {
  std::vector<Register> outRegs;
  // Get SVL in bytes (will equal total number of implemented ZA rows)
  uint64_t SVL = SVL_bits / 8;

  uint8_t base = 0;
  uint8_t tileTypeCount = 0;
  if (reg == AARCH64_REG_ZA || reg == AARCH64_REG_ZAB0) {
    // Treat ZA as byte tile : ZAB0 represents whole matrix, only 1 tile
    // Add all rows for this SVL
    // Don't need to set base as will always be 0
    tileTypeCount = 1;
  } else if (reg >= AARCH64_REG_ZAH0 && reg <= AARCH64_REG_ZAH1) {
    base = reg - AARCH64_REG_ZAH0;
    tileTypeCount = 2;
  } else if (reg >= AARCH64_REG_ZAS0 && reg <= AARCH64_REG_ZAS3) {
    base = reg - AARCH64_REG_ZAS0;
    tileTypeCount = 4;
  } else if (reg >= AARCH64_REG_ZAD0 && reg <= AARCH64_REG_ZAD7) {
    base = reg - AARCH64_REG_ZAD0;
    tileTypeCount = 8;
  } else if (reg >= AARCH64_REG_ZAQ0 && reg <= AARCH64_REG_ZAQ15) {
    base = reg - AARCH64_REG_ZAQ0;
    tileTypeCount = 16;
  }

  // Each sub-tile in ZA is allocated rows in an interleaved fashion with the
  // other sub-tiles in its group; rather than sequentially - as per the AArch64
  // specification.
  // i.e. zah0 would have rows {0,2,4,6,...}; zah1 would have rows {1,3,5,7,...}
  for (uint16_t i = 0; i < (SVL / tileTypeCount); i++) {
    outRegs.push_back(
        {RegisterType::MATRIX, uint16_t(base + (i * tileTypeCount))});
  }

  return outRegs;
}

/******************
 * DECODING LOGIC
 *****************/
void Instruction::decode() {
  if (metadata_.id == AARCH64_INS_INVALID) {
    exception_ = InstructionException::EncodingUnallocated;
    exceptionEncountered_ = true;
    return;
  }

  // Extract implicit writes, including pre/post index writeback
  for (size_t i = 0; i < metadata_.implicitDestinationCount; i++) {
    destinationRegisters_[destinationRegisterCount_] = csRegToRegister(
        static_cast<aarch64_reg>(metadata_.implicitDestinations[i]));
    destinationRegisterCount_++;
  }

  // Extract implicit reads
  for (size_t i = 0; i < metadata_.implicitSourceCount; i++) {
    // TODO: Implement FPCR usage properly
    // Ignore implicit reading of FPCR
    if (static_cast<aarch64_reg>(metadata_.implicitSources[i]) ==
        AARCH64_REG_FPCR)
      continue;
    sourceRegisters_[sourceOperandsPending_] =
        csRegToRegister(static_cast<aarch64_reg>(metadata_.implicitSources[i]));
    sourceRegisterCount_++;
    sourceOperandsPending_++;
  }

  bool accessesMemory = false;

  // Extract explicit register accesses
  for (size_t i = 0; i < metadata_.operandCount; i++) {
    const auto& op = metadata_.operands[i];

    if (op.type == AARCH64_OP_REG) {  // Register operand
      if ((op.access & cs_ac_type::CS_AC_WRITE)) {
        if (op.reg != AARCH64_REG_WZR && op.reg != AARCH64_REG_XZR) {
          // Determine the data type the instruction operates on based on the
          // register operand used
          // SME and Predicate based operations use individual op.type
          if (op.is_vreg) {
            setInstructionType(InsnType::isVectorData);
          } else if ((AARCH64_REG_Z0 <= op.reg && op.reg <= AARCH64_REG_Z31) ||
                     op.reg == AARCH64_REG_ZT0) {
            // ZT0 is an SME register, but we declare it as an SVE instruction
            // due to its 1D format.
            setInstructionType(InsnType::isSVEData);
          } else if ((op.reg <= AARCH64_REG_S31 && op.reg >= AARCH64_REG_Q0) ||
                     (op.reg <= AARCH64_REG_H31 && op.reg >= AARCH64_REG_B0)) {
            setInstructionType(InsnType::isScalarData);
          }

          // Add register writes to destinations, but skip zero-register
          // destinations
          destinationRegisters_[destinationRegisterCount_] =
              csRegToRegister(op.reg);
          destinationRegisterCount_++;
        }
      }
      if (op.access & cs_ac_type::CS_AC_READ) {
        // Add register reads to destinations
        sourceRegisters_[sourceRegisterCount_] = csRegToRegister(op.reg);
        sourceRegisterCount_++;
        sourceOperandsPending_++;

        // TODO checking of the shift type is a temporary fix to help reduce the
        // chance of incorrectly reverted aliases from being mis-classified as
        // isShift when op.shift contains garbage data. This should be reviewed
        // on the next capstone update which should remove the need to revert
        // aliasing
        if (op.shift.type > aarch64_shifter::AARCH64_SFT_INVALID &&
            op.shift.type <= aarch64_shifter::AARCH64_SFT_ROR &&
            op.shift.value > 0) {
          setInstructionType(InsnType::isShift);  // Identify shift operands
        }
      }
    } else if (op.type == AARCH64_OP_MEM) {  // Memory operand
      // Check base register exists
      if (op.mem.base != AARCH64_REG_INVALID) {
        accessesMemory = true;
        sourceRegisters_[sourceRegisterCount_] = csRegToRegister(op.mem.base);
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }
      if (op.mem.index != AARCH64_REG_INVALID) {
        // Register offset; add to sources
        sourceRegisters_[sourceRegisterCount_] = csRegToRegister(op.mem.index);
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }

    } else if (op.type == AARCH64_OP_SME) {
      setInstructionType(InsnType::isSMEData);
      std::vector<Register> regs = getZARowVectors(
          op.sme.tile, architecture_.getStreamingVectorLength());
      // Update operands structure sizes
      destinationRegisters_.addSMEOperand(regs.size());
      results_.addSMEOperand(regs.size());
      sourceRegisters_.addSMEOperand(regs.size());
      sourceValues_.addSMEOperand(regs.size());
      for (size_t i = 0; i < regs.size(); i++) {
        // If READ access, we only need to add SME rows to source registers.
        // If WRITE access, then we need to add SME rows to destination
        // registers AND source registers. The latter is required to maintain
        // any un-updated rows if an SME op will specifies
        // one row (or column) to write to.
        sourceRegisters_[sourceRegisterCount_] = regs[i];
        sourceRegisterCount_++;
        sourceOperandsPending_++;
        if (op.access & cs_ac_type::CS_AC_WRITE) {
          destinationRegisters_[destinationRegisterCount_] = regs[i];
          destinationRegisterCount_++;
        }
      }
      if (op.sme.type == AARCH64_SME_OP_TILE_VEC) {
        // SME tile has slice determined by register and immidiate.
        // Add base register to source operands
        sourceRegisters_[sourceRegisterCount_] =
            csRegToRegister(op.sme.slice_reg);
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }
    } else if (op.type == AARCH64_OP_PRED) {
      if (i == 0) setInstructionType(InsnType::isPredicate);
      if (op.access == CS_AC_READ) {
        sourceRegisters_[sourceRegisterCount_] = csRegToRegister(op.pred.reg);
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }
      if (op.access == CS_AC_WRITE) {
        destinationRegisters_[destinationRegisterCount_] =
            csRegToRegister(op.pred.reg);
        destinationRegisterCount_++;
      }
      if (op.pred.vec_select != AARCH64_REG_INVALID) {
        sourceRegisters_[sourceRegisterCount_] =
            csRegToRegister(op.pred.vec_select);
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }
    } else if (op.type == AARCH64_OP_SYSREG) {
      int32_t sysRegTag =
          architecture_.getSystemRegisterTag(op.sysop.reg.sysreg);
      // Check SYSREG is supported
      if (sysRegTag == -1) {
        exceptionEncountered_ = true;
        exception_ = InstructionException::UnmappedSysReg;
        return;
      }
      if (op.sysop.sub_type == AARCH64_OP_REG_MRS) {
        sourceRegisters_[sourceRegisterCount_] = {
            RegisterType::SYSTEM, static_cast<uint16_t>(sysRegTag)};
        sourceRegisterCount_++;
        sourceOperandsPending_++;
      }
      if (op.sysop.sub_type == AARCH64_OP_REG_MSR) {
        destinationRegisters_[destinationRegisterCount_] = {
            RegisterType::SYSTEM, static_cast<uint16_t>(sysRegTag)};
        destinationRegisterCount_++;
      }
    } else if (metadata_.operands[0].type == AARCH64_OP_SYSALIAS &&
               metadata_.operands[0].sysop.sub_type == AARCH64_OP_SVCR) {
      // This case is for instruction alias SMSTART and SMSTOP. Updating of SVCR
      // value is done via an exception so no registers required.
    }
  }

  // Identify branches
  for (size_t i = 0; i < metadata_.groupCount; i++) {
    if (metadata_.groups[i] == AARCH64_GRP_JUMP ||
        metadata_.groups[i] == AARCH64_GRP_CALL ||
        metadata_.groups[i] == AARCH64_GRP_RET ||
        metadata_.groups[i] == AARCH64_GRP_BRANCH_RELATIVE) {
      setInstructionType(InsnType::isBranch);
    }
  }

  // Identify branch type
  if (isInstruction(InsnType::isBranch)) {
    switch (metadata_.opcode) {
      case Opcode::AArch64_B:  // b label
        branchType_ = BranchType::Unconditional;
        knownOffset_ = metadata_.operands[0].imm;
        break;
      case Opcode::AArch64_BR: {  // br xn
        branchType_ = BranchType::Unconditional;
        break;
      }
      case Opcode::AArch64_BL:  // bl #imm
        branchType_ = BranchType::SubroutineCall;
        knownOffset_ = metadata_.operands[0].imm;
        break;
      case Opcode::AArch64_BLR: {  // blr xn
        branchType_ = BranchType::SubroutineCall;
        break;
      }
      case Opcode::AArch64_Bcc: {  // b.cond label
        if (metadata_.operands[0].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownOffset_ = metadata_.operands[0].imm;
        break;
      }
      case Opcode::AArch64_CBNZW:  // cbnz wn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBNZX:  // cbnz xn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBZW:  // cbz wn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBZX: {  // cbz xn, #imm
        if (metadata_.operands[1].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownOffset_ = metadata_.operands[1].imm;
        break;
      }
      case Opcode::AArch64_TBNZW:  // tbnz wn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBNZX:  // tbnz xn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBZW:  // tbz wn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBZX: {  // tbz xn, #imm, label
        if (metadata_.operands[2].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownOffset_ = metadata_.operands[2].imm;
        break;
      }
      default:
        break;
    }
  }

  // Identify loads/stores
  if (accessesMemory) {
    // Set size of data to be stored if it hasn't already been set
    if (!isMicroOp_) dataSize_ = getDataSize(metadata_.operands[0]);

    // Check first operand access to determine if it's a load or store
    if (metadata_.operands[0].access & CS_AC_WRITE) {
      if (metadata_.id == AARCH64_INS_STXR ||
          metadata_.id == AARCH64_INS_STLXR) {
        // Exceptions to this is load condition are exclusive store with a
        // success flag as first operand
        if (microOpcode_ != MicroOpcode::STR_DATA) {
          setInstructionType(InsnType::isStoreAddress);
        }
        if (microOpcode_ != MicroOpcode::STR_ADDR) {
          setInstructionType(InsnType::isStoreData);
        }
      } else {
        setInstructionType(InsnType::isLoad);
      }
    } else {
      if (microOpcode_ != MicroOpcode::STR_DATA) {
        setInstructionType(InsnType::isStoreAddress);
      }
      if (microOpcode_ != MicroOpcode::STR_ADDR) {
        setInstructionType(InsnType::isStoreData);
      }
    }

    // LDADD* are considered to be both a load and a store
    if (Opcode::AArch64_LDADDAB <= metadata_.opcode &&
        metadata_.opcode <= Opcode::AArch64_LDADDX) {
      setInstructionType(InsnType::isLoad);
      setInstructionType(InsnType::isStoreData);
    }

    // CASAL* are considered to be both a load and a store
    if (Opcode::AArch64_CASALB <= metadata_.opcode &&
        metadata_.opcode <= Opcode::AArch64_CASALX) {
      setInstructionType(InsnType::isLoad);
      setInstructionType(InsnType::isStoreData);
    }

    if (isInstruction(InsnType::isStoreData)) {
      // Identify store instruction group
      if (AARCH64_REG_Z0 <= metadata_.operands[0].reg &&
          metadata_.operands[0].reg <= AARCH64_REG_Z31) {
        setInstructionType(InsnType::isSVEData);
      } else if ((metadata_.operands[0].reg <= AARCH64_REG_S31 &&
                  metadata_.operands[0].reg >= AARCH64_REG_Q0) ||
                 (metadata_.operands[0].reg <= AARCH64_REG_H31 &&
                  metadata_.operands[0].reg >= AARCH64_REG_B0)) {
        setInstructionType(InsnType::isScalarData);
      } else if (metadata_.operands[0].is_vreg) {
        setInstructionType(InsnType::isVectorData);
      } else if ((metadata_.operands[0].reg >= AARCH64_REG_ZAB0 &&
                  metadata_.operands[0].reg <= AARCH64_REG_ZT0) ||
                 metadata_.operands[0].reg == AARCH64_REG_ZA) {
        setInstructionType(InsnType::isSMEData);
      }
    }
  } else if (microOpcode_ == MicroOpcode::STR_DATA) {
    // Edge case for identifying store data micro-operation
    setInstructionType(InsnType::isStoreData);
  }
  if (metadata_.opcode == Opcode::AArch64_LDRXl ||
      metadata_.opcode == Opcode::AArch64_LDRSWl) {
    // Literal loads aren't flagged as having a memory operand, so these must be
    // marked as loads manually
    setInstructionType(InsnType::isLoad);
  }

  // Identify Logical (bitwise) instructions
  // Opcode prefix-overlaps have been commented out but left in for clarity what
  // is searched for.
  if (metadata_.mnemonic.find("and") == 0 ||
      metadata_.mnemonic.find("bic") == 0 ||
      metadata_.mnemonic.find("bif") == 0 ||
      metadata_.mnemonic.find("bit") == 0 ||
      metadata_.mnemonic.find("bsl") == 0 ||
      metadata_.mnemonic.find("bcax") == 0 ||
      metadata_.mnemonic.find("bmop") == 0 ||
      metadata_.mnemonic.find("eor") == 0 ||
      metadata_.mnemonic.find("eon") == 0 ||
      metadata_.mnemonic.find("mvn") == 0 ||
      metadata_.mnemonic.find("not") == 0 ||
      metadata_.mnemonic.find("nand") == 0 ||
      metadata_.mnemonic.find("nbsl") == 0 ||
      metadata_.mnemonic.find("nor") == 0 ||
      metadata_.mnemonic.find("rax") == 0 ||
      metadata_.mnemonic.find("xar") == 0 ||
      metadata_.mnemonic.find("orr") == 0 ||
      metadata_.mnemonic.find("orq") == 0 ||
      metadata_.mnemonic.find("orv") == 0 ||
      metadata_.mnemonic.find("tst") == 0 ||
      metadata_.mnemonic.find("orn") == 0) {
    setInstructionType(InsnType::isLogical);
  }

  // Identify comparison insturctions (excluding atomic LD-CMP-STR)
  // Opcode prefix-overlaps have been commented out but left in for clarity what
  // is searched for.
  if (metadata_.mnemonic.find("ccmn") == 0 ||
      metadata_.mnemonic.find("cmn") == 0 ||
      metadata_.mnemonic.find("cmp") == 0 ||
      // metadata_.mnemonic.find("cmpp") == 0 ||
      // metadata_.mnemonic.find("cmpeq") == 0 ||
      // metadata_.mnemonic.find("cmpge") == 0 ||
      // metadata_.mnemonic.find("cmpgt") == 0 ||
      // metadata_.mnemonic.find("cmphi") == 0 ||
      // metadata_.mnemonic.find("cmphs") == 0 ||
      // metadata_.mnemonic.find("cmple") == 0 ||
      // metadata_.mnemonic.find("cmplo") == 0 ||
      // metadata_.mnemonic.find("cmpls") == 0 ||
      // metadata_.mnemonic.find("cmplt") == 0 ||
      // metadata_.mnemonic.find("cmpne") == 0 ||
      // metadata_.mnemonic.find("cmptst") == 0 ||
      metadata_.mnemonic.find("ccmp") == 0 ||
      metadata_.mnemonic.find("cmeq") == 0 ||
      metadata_.mnemonic.find("cmge") == 0 ||
      metadata_.mnemonic.find("cmgt") == 0 ||
      metadata_.mnemonic.find("cmtst") == 0 ||
      metadata_.mnemonic.find("cmhi") == 0 ||
      metadata_.mnemonic.find("cmhs") == 0 ||
      metadata_.mnemonic.find("cmla") == 0 ||
      metadata_.mnemonic.find("cmle") == 0 ||
      metadata_.mnemonic.find("cmlt") == 0 ||
      // The non-complete opcode prefix `fac` only yields compare uops
      metadata_.mnemonic.find("fac") == 0 ||
      // metadata_.mnemonic.find("facge") == 0 ||
      // metadata_.mnemonic.find("facgt") == 0 ||
      // metadata_.mnemonic.find("facle") == 0 ||
      // metadata_.mnemonic.find("faclt") == 0 ||
      metadata_.mnemonic.find("fccmp") == 0 ||
      // metadata_.mnemonic.find("fccmpe") == 0 ||
      metadata_.mnemonic.find("fcmp") == 0 ||
      // metadata_.mnemonic.find("fcmpe") == 0 ||
      metadata_.mnemonic.find("fcmuo") == 0 ||
      metadata_.mnemonic.find("fcmeq") == 0 ||
      metadata_.mnemonic.find("fcmge") == 0 ||
      metadata_.mnemonic.find("fcmgt") == 0 ||
      metadata_.mnemonic.find("fcmle") == 0 ||
      metadata_.mnemonic.find("fcmlt") == 0 ||
      metadata_.mnemonic.find("fcmne") == 0) {
    setInstructionType(InsnType::isCompare);
    // Capture those floating point compare instructions with no destination
    // register
    if (sourceRegisterCount_ != 0) {
      if (!(isInstruction(InsnType::isScalarData) ||
            isInstruction(InsnType::isVectorData)) &&
          sourceRegisters_[0].type == RegisterType::VECTOR) {
        setInstructionType(InsnType::isScalarData);
      }
    }
  }

  // Identify convert instructions
  // Opcode prefix-overlaps have been commented out but left in for clarity what
  // is searched for.
  if (metadata_.mnemonic.find("bfcvt") == 0 ||
      // metadata_.mnemonic.find("bfcvtn") == 0 ||
      // metadata_.mnemonic.find("bfcvtnt") == 0 ||
      metadata_.mnemonic.find("bf1cvt") == 0 ||
      // metadata_.mnemonic.find("bf1cvtl") == 0 ||
      // metadata_.mnemonic.find("bf1cvtlt") == 0 ||
      metadata_.mnemonic.find("bf2cvt") == 0 ||
      // metadata_.mnemonic.find("bf2cvtl") == 0 ||
      // metadata_.mnemonic.find("bf2cvtlt") == 0 ||
      metadata_.mnemonic.find("fcvt") == 0 ||
      // metadata_.mnemonic.find("fcvtas") == 0 ||
      // metadata_.mnemonic.find("fcvtau") == 0 ||
      // metadata_.mnemonic.find("fcvtl") == 0 ||
      // metadata_.mnemonic.find("fcvtms") == 0 ||
      // metadata_.mnemonic.find("fcvtmu") == 0 ||
      // metadata_.mnemonic.find("fcvtn") == 0 ||
      // metadata_.mnemonic.find("fcvtns") == 0 ||
      // metadata_.mnemonic.find("fcvtnu") == 0 ||
      // metadata_.mnemonic.find("fcvtps") == 0 ||
      // metadata_.mnemonic.find("fcvtpu") == 0 ||
      // metadata_.mnemonic.find("fcvtxn") == 0 ||
      // metadata_.mnemonic.find("fcvtzs") == 0 ||
      // metadata_.mnemonic.find("fcvtzu") == 0 ||
      // metadata_.mnemonic.find("fcvtlt") == 0 ||
      // metadata_.mnemonic.find("fcvtnb") == 0 ||
      // metadata_.mnemonic.find("fcvtnt") == 0 ||
      // metadata_.mnemonic.find("fcvtx") == 0 ||
      // metadata_.mnemonic.find("fcvtxnt") == 0 ||
      // metadata_.mnemonic.find("fcvtzs") == 0 ||
      // metadata_.mnemonic.find("fcvtzu") == 0 ||
      metadata_.mnemonic.find("f1cvt") == 0 ||
      // metadata_.mnemonic.find("f1cvtl") == 0 ||
      // metadata_.mnemonic.find("f1cvtlt") == 0 ||
      metadata_.mnemonic.find("f2cvt") == 0 ||
      // metadata_.mnemonic.find("f2cvtl") == 0 ||
      // metadata_.mnemonic.find("f2cvtlt") == 0 ||
      metadata_.mnemonic.find("fjcvtzs") == 0 ||
      metadata_.mnemonic.find("scvtf") == 0 ||
      metadata_.mnemonic.find("ucvtf") == 0) {
    setInstructionType(InsnType::isConvert);
    // Capture those floating point convert instructions whose destination
    // register is general purpose
    if (!(isInstruction(InsnType::isScalarData) ||
          isInstruction(InsnType::isVectorData) ||
          isInstruction(InsnType::isSVEData))) {
      setInstructionType(InsnType::isScalarData);
    }
  }

  // Identify divide or square root operations
  // Opcode prefix-overlaps have been commented out but left in for clarity what
  // is searched for.
  if (metadata_.mnemonic.find("sdiv") == 0 ||
      // metadata_.mnemonic.find("sdivr") == 0 ||
      metadata_.mnemonic.find("udiv") == 0 ||
      // metadata_.mnemonic.find("udivr") == 0 ||
      metadata_.mnemonic.find("fdiv") == 0 ||
      // metadata_.mnemonic.find("fdivr") == 0 ||
      // The non-complete opcode prefix `frsqrt` only yields divSqrt uops
      metadata_.mnemonic.find("frsqrt") == 0 ||
      // metadata_.mnemonic.find("frsqrte") == 0 ||
      // metadata_.mnemonic.find("frsqrts") == 0 ||
      metadata_.mnemonic.find("fsqrt") == 0 ||
      metadata_.mnemonic.find("ursqrte") == 0) {
    setInstructionType(InsnType::isDivideOrSqrt);
  }

  // Identify multiply operations
  // Opcode prefix-overlaps have been commented out but left in for clarity what
  // is searched for.
  if (metadata_.mnemonic.find("bfmmla") == 0 ||
      metadata_.mnemonic.find("bfmul") == 0 ||
      // The non-complete opcode prefix `bfml` only yields multiply uops
      metadata_.mnemonic.find("bfml") == 0 ||
      // metadata_.mnemonic.find("bfmla") == 0 ||
      // metadata_.mnemonic.find("bfmlalb") == 0 ||
      // metadata_.mnemonic.find("bfmlalt") == 0 ||
      // metadata_.mnemonic.find("bfmlal") == 0 ||
      // metadata_.mnemonic.find("bfmls") == 0 ||
      // metadata_.mnemonic.find("bfmlslb") == 0 ||
      // metadata_.mnemonic.find("bfmlslt") == 0 ||
      // metadata_.mnemonic.find("bfmlsl") == 0 ||
      metadata_.mnemonic.find("cmla") == 0 ||
      // The substring `dot` only appears in dot-product opcodes
      metadata_.mnemonic.find("dot") != std::string::npos ||
      // metadata_.mnemonic.find("bfdot") == 0 ||
      // metadata_.mnemonic.find("bfvdot") == 0 ||
      // metadata_.mnemonic.find("fdot") == 0 ||
      // metadata_.mnemonic.find("fvdot") == 0 ||
      // metadata_.mnemonic.find("fvdotb") == 0 ||
      // metadata_.mnemonic.find("fvdott") == 0 ||
      // metadata_.mnemonic.find("sdot") == 0 ||
      // metadata_.mnemonic.find("sudot") == 0 ||
      // metadata_.mnemonic.find("suvdot") == 0 ||
      // metadata_.mnemonic.find("udot") == 0 ||
      // metadata_.mnemonic.find("usdot") == 0 ||
      // metadata_.mnemonic.find("usvdot") == 0 ||
      // metadata_.mnemonic.find("uvdot") == 0 ||
      // metadata_.mnemonic.find("cdot") == 0 ||
      metadata_.mnemonic.find("fmla") == 0 ||
      // metadata_.mnemonic.find("fmlal") == 0 ||
      // metadata_.mnemonic.find("fmlal2") == 0 ||
      // metadata_.mnemonic.find("fmlalb") == 0 ||
      // metadata_.mnemonic.find("fmlalt") == 0 ||
      // metadata_.mnemonic.find("fmlallbb") == 0 ||
      // metadata_.mnemonic.find("fmlallbt") == 0 ||
      // metadata_.mnemonic.find("fmlalltb") == 0 ||
      // metadata_.mnemonic.find("fmlalltt") == 0 ||
      // metadata_.mnemonic.find("fmlall") == 0 ||
      metadata_.mnemonic.find("fmls") == 0 ||
      // metadata_.mnemonic.find("fmlsl") == 0 ||
      // metadata_.mnemonic.find("fmlsl2") == 0 ||
      // metadata_.mnemonic.find("fmlslb") == 0 ||
      // metadata_.mnemonic.find("fmlslt") == 0 ||
      metadata_.mnemonic.find("fmul") == 0 ||
      // metadata_.mnemonic.find("fmulx") == 0 ||
      metadata_.mnemonic.find("fmad") == 0 ||
      // metadata_.mnemonic.find("fmadd") == 0 ||
      metadata_.mnemonic.find("fmmla") == 0 ||
      metadata_.mnemonic.find("fmsb") == 0 ||
      metadata_.mnemonic.find("fmsub") == 0 ||
      metadata_.mnemonic.find("ftmad") == 0 ||
      metadata_.mnemonic.find("fcmla") == 0 ||
      // The non-complete opcode prefix `fnm` only yields multiply uops
      metadata_.mnemonic.find("fnm") == 0 ||
      // metadata_.mnemonic.find("fnmad") == 0 ||
      // metadata_.mnemonic.find("fnmla") == 0 ||
      // metadata_.mnemonic.find("fnmls") == 0 ||
      // metadata_.mnemonic.find("fnmsb") == 0 ||
      // metadata_.mnemonic.find("fnmadd") == 0 ||
      // metadata_.mnemonic.find("fnmsub") == 0 ||
      // metadata_.mnemonic.find("fnmul") == 0 ||
      metadata_.mnemonic.find("madd") == 0 ||
      // metadata_.mnemonic.find("maddpt") == 0 ||
      metadata_.mnemonic.find("mul") == 0 ||
      metadata_.mnemonic.find("mla") == 0 ||
      // metadata_.mnemonic.find("mlapt") == 0 ||
      metadata_.mnemonic.find("mls") == 0 ||
      metadata_.mnemonic.find("mneg") == 0 ||
      metadata_.mnemonic.find("msub") == 0 ||
      // metadata_.mnemonic.find("msubpt") == 0 ||
      metadata_.mnemonic.find("mad") == 0 ||
      // metadata_.mnemonic.find("madpt") == 0 ||
      metadata_.mnemonic.find("msb") == 0 ||
      // The substring `mop` only appears in outer-product opcodes
      metadata_.mnemonic.find("mop") != std::string::npos ||
      // metadata_.mnemonic.find("bfmopa") == 0 ||
      // metadata_.mnemonic.find("bfmops") == 0 ||
      // metadata_.mnemonic.find("bmopa") == 0 ||
      // metadata_.mnemonic.find("bmops") == 0 ||
      // metadata_.mnemonic.find("fmopa") == 0 ||
      // metadata_.mnemonic.find("fmops") == 0 ||
      // metadata_.mnemonic.find("smopa") == 0 ||
      // metadata_.mnemonic.find("smops") == 0 ||
      // metadata_.mnemonic.find("sumopa") == 0 ||
      // metadata_.mnemonic.find("sumops") == 0 ||
      // metadata_.mnemonic.find("umopa") == 0 ||
      // metadata_.mnemonic.find("umops") == 0 ||
      // metadata_.mnemonic.find("usmopa") == 0 ||
      // metadata_.mnemonic.find("usmops") == 0
      metadata_.mnemonic.find("pmul") == 0 ||
      // metadata_.mnemonic.find("pmull") == 0 ||
      // metadata_.mnemonic.find("pmull2") == 0 ||
      // metadata_.mnemonic.find("pmullb") == 0 ||
      // metadata_.mnemonic.find("pmullt") == 0 ||
      // The non-complete opcode prefix `sml` only yields multiply uops
      metadata_.mnemonic.find("sml") == 0 ||
      // metadata_.mnemonic.find("smlalb") == 0 ||
      // metadata_.mnemonic.find("smlalt") == 0 ||
      // metadata_.mnemonic.find("smlslb") == 0 ||
      // metadata_.mnemonic.find("smlslt") == 0 ||
      // metadata_.mnemonic.find("smlal") == 0 ||
      // metadata_.mnemonic.find("smlal2") == 0 ||
      // metadata_.mnemonic.find("smlsl") == 0 ||
      // metadata_.mnemonic.find("smlsl2") == 0 ||
      // metadata_.mnemonic.find("smlall") == 0 ||
      // metadata_.mnemonic.find("smlsll") == 0 ||
      metadata_.mnemonic.find("smmla") == 0 ||
      // The non-complete opcode prefix `smul` only yields multiply uops
      metadata_.mnemonic.find("smul") == 0 ||
      // metadata_.mnemonic.find("smulh") == 0 ||
      // metadata_.mnemonic.find("smull") == 0 ||
      // metadata_.mnemonic.find("smull2") == 0 ||
      // metadata_.mnemonic.find("smullb") == 0 ||
      // metadata_.mnemonic.find("smullt") == 0 ||
      // The non-complete opcode prefix `sqdm` only yields multiply uops
      metadata_.mnemonic.find("sqdm") == 0 ||
      // metadata_.mnemonic.find("sqdmlal") == 0 ||
      // metadata_.mnemonic.find("sqdmlal2") == 0 ||
      // metadata_.mnemonic.find("sqdmlsl") == 0 ||
      // metadata_.mnemonic.find("sqdmlsl2") == 0 ||
      // metadata_.mnemonic.find("sqdmulh") == 0 ||
      // metadata_.mnemonic.find("sqdmull") == 0 ||
      // metadata_.mnemonic.find("sqdmull2") == 0 ||
      // metadata_.mnemonic.find("sqdmlalb") == 0 ||
      // metadata_.mnemonic.find("sqdmlalbt") == 0 ||
      // metadata_.mnemonic.find("sqdmlalt") == 0 ||
      // metadata_.mnemonic.find("sqdmlslb") == 0 ||
      // metadata_.mnemonic.find("sqdmlslbt") == 0 ||
      // metadata_.mnemonic.find("sqdmlslt") == 0 ||
      // metadata_.mnemonic.find("sqdmullb") == 0 ||
      // metadata_.mnemonic.find("sqdmullt") == 0 ||
      // The non-complete opcode prefix `sqrd` only yields multiply uops
      metadata_.mnemonic.find("sqrd") == 0 ||
      // metadata_.mnemonic.find("sqrdmlah") == 0 ||
      // metadata_.mnemonic.find("sqrdmlsh") == 0 ||
      // metadata_.mnemonic.find("sqrdmulh") == 0 ||
      // metadata_.mnemonic.find("sqrdcmlah") == 0 ||
      metadata_.mnemonic.find("sumlall") == 0 ||
      metadata_.mnemonic.find("smaddl") == 0 ||
      metadata_.mnemonic.find("smnegl") == 0 ||
      metadata_.mnemonic.find("smsubl") == 0 ||
      // The non-complete opcode prefix `umul` only yields multiply uops
      metadata_.mnemonic.find("umul") == 0 ||
      // metadata_.mnemonic.find("umulh") == 0 ||
      // metadata_.mnemonic.find("umull") == 0 ||
      // metadata_.mnemonic.find("umull2") == 0 ||
      // metadata_.mnemonic.find("umullb") == 0 ||
      // metadata_.mnemonic.find("umullt") == 0 ||
      // The non-complete opcode prefix `uml` only yields multiply uops
      metadata_.mnemonic.find("uml") == 0 ||
      // metadata_.mnemonic.find("umlal") == 0 ||
      // metadata_.mnemonic.find("umlal2") == 0 ||
      // metadata_.mnemonic.find("umlsl") == 0 ||
      // metadata_.mnemonic.find("umlsl2") == 0 ||
      // metadata_.mnemonic.find("umlslt") == 0 ||
      // metadata_.mnemonic.find("umlalb") == 0 ||
      // metadata_.mnemonic.find("umlalt") == 0 ||
      // metadata_.mnemonic.find("umlslb") == 0 ||
      // metadata_.mnemonic.find("umlall") == 0 ||
      // metadata_.mnemonic.find("umlsll") == 0 ||
      metadata_.mnemonic.find("usmlall") == 0 ||
      metadata_.mnemonic.find("usmmla") == 0 ||
      metadata_.mnemonic.find("ummla") == 0 ||
      metadata_.mnemonic.find("umaddl") == 0 ||
      metadata_.mnemonic.find("umnegl") == 0 ||
      metadata_.mnemonic.find("umsubl") == 0) {
    setInstructionType(InsnType::isMultiply);
  }

  // Catch exceptions to the above identifier assignments
  // Uncaught predicate assignment due to lacking destination register
  if (metadata_.opcode == Opcode::AArch64_PTEST_PP) {
    setInstructionType(InsnType::isPredicate);
  }
  // Uncaught float data assignment for FMOV move to general instructions
  if (((Opcode::AArch64_FMOVD0 <= metadata_.opcode &&
        metadata_.opcode <= Opcode::AArch64_FMOVS0) ||
       (Opcode::AArch64_FMOVDXHighr <= metadata_.opcode &&
        metadata_.opcode <= Opcode::AArch64_FMOVv8f16_ns)) &&
      !(isInstruction(InsnType::isScalarData) ||
        isInstruction(InsnType::isVectorData))) {
    setInstructionType(InsnType::isScalarData);
  }
  // Uncaught vector data assignment for SMOV and UMOV instructions
  if ((Opcode::AArch64_SMOVvi16to32 <= metadata_.opcode &&
       metadata_.opcode <= Opcode::AArch64_SMOVvi8to64_idx0) ||
      (Opcode::AArch64_UMOVvi16 <= metadata_.opcode &&
       metadata_.opcode <= Opcode::AArch64_UMOVvi8_idx0)) {
    setInstructionType(InsnType::isVectorData);
  }
  // Uncaught float data assignment for FCVT convert to general instructions
  if ((Opcode::AArch64_FCVTASUWDr <= metadata_.opcode &&
       metadata_.opcode <= Opcode::AArch64_FCVT_ZPmZ_StoH) &&
      !(isInstruction(InsnType::isScalarData) ||
        isInstruction(InsnType::isVectorData))) {
    setInstructionType(InsnType::isScalarData);
  }

  // if (!(isInstruction(InsnType::isSMEData))) {
  // Catch zero register references and pre-complete those operands - not
  // applicable to SME instructions
  for (uint16_t i = 0; i < sourceRegisterCount_; i++) {
    if (sourceRegisters_[i] == RegisterType::ZERO_REGISTER) {
      sourceValues_[i] = RegisterValue(0, 8);
      sourceOperandsPending_--;
    }
  }
  // } else {
  if (isInstruction(InsnType::isSMEData)) {
    // For SME instructions, resize the following structures to have the
    // exact amount of space required
    sourceRegisters_.resize(sourceRegisterCount_);
    destinationRegisters_.resize(destinationRegisterCount_);
    sourceValues_.resize(sourceRegisterCount_);
    results_.resize(destinationRegisterCount_);
  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng