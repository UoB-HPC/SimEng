#include <unordered_set>

#include "InstructionMetadata.hh"

#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {
namespace arch {
namespace aarch64 {

/**************************
 * HELPER DATA STRUCTURES
 **************************/

static const std::unordered_set<std::string> logicalOps = {
    "and", "bic", "bif", "bit", "bsl",  "bcax", "bmop",
    "eor", "eon", "mvn", "not", "nand", "nbsl", "nor",
    "rax", "xar", "orr", "orq", "orv",  "tst",  "orn"};

static const std::unordered_set<std::string> cmpOps = {
    "ccmn",   "cmn",   "cmp",   "cmpp",   "cmpeq", "cmpge", "cmpgt",
    "cmphi",  "cmphs", "cmple", "cmplo",  "cmpls", "cmplt", "cmpne",
    "cmptst", "ccmp",  "cmeq",  "cmge",   "cmgt",  "cmtst", "cmhi",
    "cmhs",   "cmla",  "cmle",  "cmlt",   "fac",   "facge", "facgt",
    "facle",  "faclt", "fccmp", "fccmpe", "fcmp",  "fcmpe", "fcmuo",
    "fcmeq",  "fcmge", "fcmgt", "fcmle",  "fcmlt", "fcmne"};

static const std::unordered_set<std::string> cvtOps = {
    "bfcvt",   "bfcvtn",  "bfcvtnt",  "bf1cvt",  "bf1cvtl", "bf1cvtlt",
    "bf2cvt",  "bf2cvtl", "bf2cvtlt", "fcvt",    "fcvtas",  "fcvtau",
    "fcvtl",   "fcvtms",  "fcvtmu",   "fcvtn",   "fcvtns",  "fcvtnu",
    "fcvtps",  "fcvtpu",  "fcvtxn",   "fcvtzs",  "fcvtzu",  "fcvtlt",
    "fcvtnb",  "fcvtnt",  "fcvtx",    "fcvtxnt", "fcvtzs",  "fcvtzu",
    "f1cvt",   "f1cvtl",  "f1cvtlt",  "f2cvt",   "f2cvtl",  "f2cvtlt",
    "fjcvtzs", "scvtf",   "ucvtf"};

static const std::unordered_set<std::string> divsqrtOps = {
    "sdiv",   "sdivr",   "udiv",    "udivr", "fdiv",   "fdivr",
    "frsqrt", "frsqrte", "frsqrts", "fsqrt", "ursqrte"};

static const std::unordered_set<std::string> mulOps = {
    "bfmmla",   "bfmul",     "bfml",     "bfmla",     "bfmlalb",   "bfmlalt",
    "bfmlal",   "bfmls",     "bfmlslb",  "bfmlslt",   "bfmlsl",    "cmla",
    "dot",      "bfdot",     "bfvdot",   "fdot",      "fvdot",     "fvdotb",
    "fvdott",   "sdot",      "sudot",    "suvdot",    "udot",      "usdot",
    "usvdot",   "uvdot",     "cdot",     "fmla",      "fmlal",     "fmlal2",
    "fmlalb",   "fmlalt",    "fmlallbb", "fmlallbt",  "fmlalltb",  "fmlalltt",
    "fmlall",   "fmls",      "fmlsl",    "fmlsl2",    "fmlslb",    "fmlslt",
    "fmul",     "fmulx",     "fmad",     "fmadd",     "fmmla",     "fmsb",
    "fmsub",    "ftmad",     "fcmla",    "fnm",       "fnmad",     "fnmla",
    "fnmls",    "fnmsb",     "fnmadd",   "fnmsub",    "fnmul",     "madd",
    "maddpt",   "mul",       "mla",      "mlapt",     "mls",       "mneg",
    "msub",     "msubpt",    "mad",      "madpt",     "msb",       "mop",
    "bfmopa",   "bfmops",    "bmopa",    "bmops",     "fmopa",     "fmops",
    "smopa",    "smops",     "sumopa",   "sumops",    "umopa",     "umops",
    "usmopa",   "usmops",    "pmul",     "pmull",     "pmull2",    "pmullb",
    "pmullt",   "sml",       "smlalb",   "smlalt",    "smlslb",    "smlslt",
    "smlal",    "smlal2",    "smlsl",    "smlsl2",    "smlall",    "smlsll",
    "smmla",    "smul",      "smulh",    "smull",     "smull2",    "smullb",
    "smullt",   "sqdm",      "sqdmlal",  "sqdmlal2",  "sqdmlsl",   "sqdmlsl2",
    "sqdmulh",  "sqdmull",   "sqdmull2", "sqdmlalb",  "sqdmlalbt", "sqdmlalt",
    "sqdmlslb", "sqdmlslbt", "sqdmlslt", "sqdmullb",  "sqdmullt",  "sqrd",
    "sqrdmlah", "sqrdmlsh",  "sqrdmulh", "sqrdcmlah", "sumlall",   "smaddl",
    "smnegl",   "smsubl",    "umul",     "umulh",     "umull",     "umull2",
    "umullb",   "umullt",    "uml",      "umlal",     "umlal2",    "umlsl",
    "umlsl2",   "umlslt",    "umlalb",   "umlalt",    "umlslb",    "umlall",
    "umlsll",   "usmlall",   "usmmla",   "ummla",     "umaddl",    "umnegl",
    "umsubl"};

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
  // Occupy same registers as (P) predicates but use a different encoding.
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

        // Identify shift operands
        if (op.shift.type != aarch64_shifter::AARCH64_SFT_INVALID &&
            op.shift.value > 0) {
          setInstructionType(InsnType::isShift);
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
        // Early check for WZR/XZR registers used as scalar index. Allows SME
        // instructions to avoid checking all source operands later on.
        if (sourceRegisters_[sourceRegisterCount_] ==
            RegisterType::ZERO_REGISTER) {
          sourceValues_[sourceRegisterCount_] = RegisterValue(0, 8);
        } else {
          sourceOperandsPending_++;
        }
        sourceRegisterCount_++;
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
      } else if (op.sysop.sub_type == AARCH64_OP_REG_MSR) {
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
      case Opcode::AArch64_RET:  // ret {xt}
        branchType_ = BranchType::Return;
        break;
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
    // Literal loads aren't flagged as having a memory operand, so these must
    // be marked as loads manually
    setInstructionType(InsnType::isLoad);
  }

  // Identify Logical (bitwise) instructions
  if (logicalOps.find(metadata_.mnemonic) != logicalOps.end()) {
    setInstructionType(InsnType::isLogical);
  }

  // Identify comparison insturctions (excluding atomic LD-CMP-STR)
  if (cmpOps.find(metadata_.mnemonic) != cmpOps.end()) {
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
  if (cvtOps.find(metadata_.mnemonic) != cvtOps.end()) {
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
  if (divsqrtOps.find(metadata_.mnemonic) != divsqrtOps.end()) {
    setInstructionType(InsnType::isDivideOrSqrt);
  }

  // Identify multiply operations
  if (mulOps.find(metadata_.mnemonic) != mulOps.end()) {
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
        metadata_.opcode <= Opcode::AArch64_FMOVXHr)) &&
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

  if (!(isInstruction(InsnType::isSMEData))) {
    // Catch zero register references and pre-complete those operands - not
    // applicable to SME instructions
    for (uint16_t i = 0; i < sourceRegisterCount_; i++) {
      if (sourceRegisters_[i] == RegisterType::ZERO_REGISTER) {
        sourceValues_[i] = RegisterValue(0, 8);
        sourceOperandsPending_--;
      }
    }
  } else {
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