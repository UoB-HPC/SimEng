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

// Generate a general purpose register identifier with tag `tag`
constexpr Register genReg(uint16_t tag) { return {RegisterType::GENERAL, tag}; }
// Generate a NZCV register identifier
constexpr Register nzcvReg() { return {RegisterType::NZCV, 0}; }

// Sign-extend a bitstring of length `currentLength`
constexpr int32_t signExtend(uint32_t value, int currentLength) {
  uint32_t mask = (0xFFFFFFFF) << currentLength;
  bool negative = bit(value, currentLength - 1);
  return static_cast<int32_t>(value) | (negative ? mask : 0);
}

/** Parses the Capstone `arm64_reg` value to generate an architectural register
 * representation.
 *
 * WARNING: this conversion is FRAGILE, and relies on the structure of the
 * `arm64_reg` enum. Updates to the Capstone library version may cause this to
 * break. */
Register csRegToRegister(arm64_reg reg) {
  // Check from top of the range downwards

  // ARM64_REG_V0 -> {end} are vector registers, reading from the vector file
  if (reg >= ARM64_REG_V0) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - ARM64_REG_V0)};
  }

  // ARM64_REG_Z0 -> +31 are scalable vector registers (Z) registers, reading
  // from the vector file
  if (reg >= ARM64_REG_Z0) {
    return {RegisterType::VECTOR, static_cast<uint16_t>(reg - ARM64_REG_Z0)};
  }

  // ARM64_REG_X0 -> +28 are 64-bit (X) registers, reading from the general
  // file. Excludes #29 (FP) and #30 (LR)
  if (reg >= ARM64_REG_X0) {
    return {RegisterType::GENERAL, static_cast<uint16_t>(reg - ARM64_REG_X0)};
  }

  // ARM64_REG_W0 -> +30 are 32-bit (W) registers, reading from the general
  // file. Excludes #31 (WZR/WSP).
  if (reg >= ARM64_REG_W0) {
    return {RegisterType::GENERAL, static_cast<uint16_t>(reg - ARM64_REG_W0)};
  }

  // ARM64_REG_Q0 and above are repeated ranges representing scalar access
  // specifiers on the vector registers with arrangements Q and S, each
  // covering 32 registers
  if (reg >= ARM64_REG_Q0) {
    return {RegisterType::VECTOR,
            static_cast<uint16_t>((reg - ARM64_REG_Q0) % 32)};
  }

  // ARM64_REG_P0 -> +15 are 256-bit (P) registers. Excludes #16 (FFR).
  if (reg >= ARM64_REG_P0) {
    return {RegisterType::PREDICATE, static_cast<uint16_t>(reg - ARM64_REG_P0)};
  }

  // ARM64_REG_Q0 and above are repeated ranges representing scalar access
  // specifiers on the vector registers with arrangements B, D and H, each
  // covering 32 registers
  if (reg >= ARM64_REG_B0) {
    return {RegisterType::VECTOR,
            static_cast<uint16_t>((reg - ARM64_REG_B0) % 32)};
  }

  // ARM64_REG_WZR and _XZR are zero registers, and don't read
  if (reg == ARM64_REG_WZR || reg == ARM64_REG_XZR) {
    return Instruction::ZERO_REGISTER;
  }

  // ARM64_REG_SP and _WSP are stack pointer registers, stored in r31 of the
  // general file
  if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) {
    return {RegisterType::GENERAL, 31};
  }

  // ARM64_REG_NZCV is the condition flags register
  if (reg == ARM64_REG_NZCV) {
    return {RegisterType::NZCV, 0};
  }
  // ARM64_REG_X29 is the frame pointer, stored in r29 of the general file
  if (reg == ARM64_REG_X29) {
    return {RegisterType::GENERAL, 29};
  }
  // ARM64_REG_X30 is the link register, stored in r30 of the general file
  if (reg == ARM64_REG_X30) {
    return {RegisterType::GENERAL, 30};
  }

  if (reg == ARM64_REG_FFR) {
    return {RegisterType::PREDICATE, 16};
  }

  assert(false && "Decoding failed due to unknown register identifier");
  return {std::numeric_limits<uint8_t>::max(),
          std::numeric_limits<uint16_t>::max()};
}

// Check for and mark WZR/XZR references
const Register& filterZR(const Register& reg) {
  return (reg.type == RegisterType::GENERAL && reg.tag == 31
              ? Instruction::ZERO_REGISTER
              : reg);
}

void Instruction::checkZeroReg() {
  if (sourceRegisters[sourceRegisterCount] == Instruction::ZERO_REGISTER) {
    // Catch zero register references and pre-complete those operands
    operands[sourceRegisterCount] = RegisterValue(0, 8);
  } else {
    operandsPending++;
  }
}

/******************
 * DECODING LOGIC
 *****************/
void Instruction::decode() {
  if (metadata.id == ARM64_INS_INVALID) {
    exception_ = InstructionException::EncodingUnallocated;
    exceptionEncountered_ = true;
    return;
  }

  // Extract implicit writes
  for (size_t i = 0; i < metadata.implicitDestinationCount; i++) {
    destinationRegisters[destinationRegisterCount] = csRegToRegister(
        static_cast<arm64_reg>(metadata.implicitDestinations[i]));
    destinationRegisterCount++;
  }
  // Extract implicit reads
  for (size_t i = 0; i < metadata.implicitSourceCount; i++) {
    sourceRegisters[sourceRegisterCount] =
        csRegToRegister(static_cast<arm64_reg>(metadata.implicitSources[i]));
    checkZeroReg();
    sourceRegisterCount++;
  }

  bool accessesMemory = false;

  // Extract explicit register accesses
  for (size_t i = 0; i < metadata.operandCount; i++) {
    const auto& op = metadata.operands[i];

    if (op.type == ARM64_OP_REG) {  // Register operand
      if ((op.access & cs_ac_type::CS_AC_WRITE) && op.reg != ARM64_REG_WZR &&
          op.reg != ARM64_REG_XZR) {
        // Add register writes to destinations, but skip zero-register
        // destinations
        destinationRegisters[destinationRegisterCount] =
            csRegToRegister(op.reg);
        destinationRegisterCount++;
        // Belongs to the predicate group if the detsination register is a
        // predicate
        // Determine the data type the instruction operates on based on the
        // register operand used
        if (op.reg >= ARM64_REG_V0) {
          isVectorData_ = true;
        } else if (op.reg >= ARM64_REG_Z0) {
          isSVEData_ = true;
        } else if (op.reg <= ARM64_REG_S31 && op.reg >= ARM64_REG_Q0) {
          isScalarData_ = true;
        } else if (op.reg <= ARM64_REG_P15 && op.reg >= ARM64_REG_P0) {
          isPredicate_ = true;
        } else if (op.reg <= ARM64_REG_H31 && op.reg >= ARM64_REG_B0) {
          isScalarData_ = true;
        }
      }
      if (op.access & cs_ac_type::CS_AC_READ) {
        // Add register reads to destinations
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);

        checkZeroReg();

        if (op.shift.value > 0) isNoShift_ = false;  // Identify shift operands

        sourceRegisterCount++;
      }
    } else if (op.type == ARM64_OP_MEM) {  // Memory operand
      accessesMemory = true;
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.base);

      checkZeroReg();
      sourceRegisterCount++;

      if (metadata.writeback) {
        // Writeback instructions modify the base address
        destinationRegisters[destinationRegisterCount] =
            csRegToRegister(op.mem.base);
        destinationRegisterCount++;
      }
      if (op.mem.index) {
        // Register offset; add to sources
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.index);

        checkZeroReg();
        sourceRegisterCount++;
      }
    } else if (op.type == ARM64_OP_REG_MRS) {
      int32_t sysRegTag = architecture_.getSystemRegisterTag(op.imm);
      if (sysRegTag == -1) {
        exceptionEncountered_ = true;
        exception_ = InstructionException::UnmappedSysReg;
      } else {
        sourceRegisters[sourceRegisterCount] = {
            RegisterType::SYSTEM, static_cast<uint16_t>(sysRegTag)};
        sourceRegisterCount++;
        operandsPending++;
      }
    } else if (op.type == ARM64_OP_REG_MSR) {
      int32_t sysRegTag = architecture_.getSystemRegisterTag(op.imm);
      if (sysRegTag == -1) {
        exceptionEncountered_ = true;
        exception_ = InstructionException::UnmappedSysReg;
      } else {
        destinationRegisters[destinationRegisterCount] = {
            RegisterType::SYSTEM, static_cast<uint16_t>(sysRegTag)};
        destinationRegisterCount++;
      }
    }
  }

  // Identify branches
  for (size_t i = 0; i < metadata.groupCount; i++) {
    if (metadata.groups[i] == ARM64_GRP_JUMP) {
      isBranch_ = true;
    }
  }

  // Identify branch type
  if (isBranch_) {
    switch (metadata.opcode) {
      case Opcode::AArch64_B:  // b label
        branchType_ = BranchType::Unconditional;
        knownTarget_ = metadata.operands[0].imm;
        break;
      case Opcode::AArch64_BR: {  // br xn
        branchType_ = BranchType::Unconditional;
        break;
      }
      case Opcode::AArch64_BL:  // bl #imm
        branchType_ = BranchType::SubroutineCall;
        knownTarget_ = metadata.operands[0].imm;
        break;
      case Opcode::AArch64_BLR: {  // blr xn
        branchType_ = BranchType::SubroutineCall;
        break;
      }
      case Opcode::AArch64_Bcc: {  // b.cond label
        if (metadata.operands[0].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownTarget_ = metadata.operands[0].imm;
        break;
      }
      case Opcode::AArch64_CBNZW:  // cbnz wn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBNZX:  // cbnz xn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBZW:  // cbz wn, #imm
        [[fallthrough]];
      case Opcode::AArch64_CBZX: {  // cbz xn, #imm
        if (metadata.operands[1].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownTarget_ = metadata.operands[1].imm;
        break;
      }
      case Opcode::AArch64_TBNZW:  // tbnz wn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBNZX:  // tbnz xn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBZW:  // tbz wn, #imm, label
        [[fallthrough]];
      case Opcode::AArch64_TBZX: {  // tbz xn, #imm, label
        if (metadata.operands[2].imm < 0)
          branchType_ = BranchType::LoopClosing;
        else
          branchType_ = BranchType::Conditional;
        knownTarget_ = metadata.operands[2].imm;
        break;
      }
      case Opcode::AArch64_RET: {  // ret {xr}
        branchType_ = BranchType::Return;
        break;
      }
      default:
        break;
    }
  }

  // Identify loads/stores
  if (accessesMemory) {
    // Set size of data to be stored if it hasn't already been set
    if (!isMicroOp_) dataSize_ = getDataSize(metadata.operands[0]);

    // Check first operand access to determine if it's a load or store
    if (metadata.operands[0].access & CS_AC_WRITE) {
      if (metadata.id == ARM64_INS_STXR || metadata.id == ARM64_INS_STLXR) {
        // Exceptions to this is load condition are exclusive store with a
        // success flag as first operand
        if (microOpcode_ != MicroOpcode::STR_DATA) {
          isStoreAddress_ = true;
        }
        if (microOpcode_ != MicroOpcode::STR_ADDR) {
          isStoreData_ = true;
        }
      } else {
        isLoad_ = true;
      }
    } else {
      if (microOpcode_ != MicroOpcode::STR_DATA) {
        isStoreAddress_ = true;
      }
      if (microOpcode_ != MicroOpcode::STR_ADDR) {
        isStoreData_ = true;
      }
    }

    // LDADD* are considered to be both a load and a store
    if (metadata.id >= ARM64_INS_LDADD && metadata.id <= ARM64_INS_LDADDLH) {
      isLoad_ = true;
    }

    // CASAL* are considered to be both a load and a store
    if (metadata.opcode == Opcode::AArch64_CASALW ||
        metadata.opcode == Opcode::AArch64_CASALX) {
      isLoad_ = true;
    }

    if (isStoreData_) {
      // Identify whether a store operation uses Z source registers
      if (ARM64_REG_Z0 <= metadata.operands[0].reg &&
          metadata.operands[0].reg <= ARM64_REG_Z31) {
        isSVEData_ = true;
      }
    }
  } else if (microOpcode_ == MicroOpcode::STR_DATA) {
    // Edge case for identifying store data micro-operation
    isStoreData_ = true;
  }
  if (metadata.opcode == Opcode::AArch64_LDRXl ||
      metadata.opcode == Opcode::AArch64_LDRSWl) {
    // Literal loads aren't flagged as having a memory operand, so these must be
    // marked as loads manually
    isLoad_ = true;
  }

  if ((264 <= metadata.opcode && metadata.opcode <= 267) ||    // AND
      (1063 <= metadata.opcode && metadata.opcode <= 1084) ||  // AND (pt.2)
      (284 <= metadata.opcode && metadata.opcode <= 287) ||    // BIC
      (1167 <= metadata.opcode && metadata.opcode <= 1183) ||  // BIC (pt.2)
      (321 <= metadata.opcode && metadata.opcode <= 324) ||    // EOR/EON
      (1707 <= metadata.opcode && metadata.opcode <= 1736) ||  // EOR/EON (pt.2)
      (771 <= metadata.opcode && metadata.opcode <= 774) ||    // ORR/ORN
      (3748 <= metadata.opcode && metadata.opcode <= 3771)) {  // ORR/ORN (pt.2)
    isLogical_ = true;
  }

  if ((1252 <= metadata.opcode && metadata.opcode <= 1259) ||
      (1314 <= metadata.opcode && metadata.opcode <= 1501) ||
      (1778 <= metadata.opcode && metadata.opcode <= 1799) ||
      (1842 <= metadata.opcode && metadata.opcode <= 1969)) {
    isCompare_ = true;
    // Capture those floating point compare instructions with no destination
    // register
    if (!(isScalarData_ || isVectorData_) &&
        sourceRegisters[0].type == RegisterType::VECTOR) {
      isScalarData_ = true;
    }
  }

  if ((347 <= metadata.opcode && metadata.opcode <= 366) ||
      (1142 <= metadata.opcode && metadata.opcode <= 1146) ||
      (1976 <= metadata.opcode && metadata.opcode <= 2186) ||
      (metadata.opcode == 2207) ||
      (782 <= metadata.opcode && metadata.opcode <= 788) ||
      (4063 <= metadata.opcode && metadata.opcode <= 4097) ||
      (898 <= metadata.opcode && metadata.opcode <= 904) ||
      (5608 <= metadata.opcode && metadata.opcode <= 5642)) {
    isConvert_ = true;
    // Capture those floating point convert instructions whose destination
    // register is general purpose
    if (!(isScalarData_ || isVectorData_ || isSVEData_)) {
      isScalarData_ = true;
    }
  }

  // Identify divide or square root operations
  if ((367 <= metadata.opcode && metadata.opcode <= 375) ||
      (789 <= metadata.opcode && metadata.opcode <= 790) ||
      (905 <= metadata.opcode && metadata.opcode <= 906) ||
      (2187 <= metadata.opcode && metadata.opcode <= 2200) ||
      (4098 <= metadata.opcode && metadata.opcode <= 4103) ||
      (5644 <= metadata.opcode && metadata.opcode <= 5649) ||
      (481 <= metadata.opcode && metadata.opcode <= 483) ||
      (metadata.opcode == 940) ||
      (2640 <= metadata.opcode && metadata.opcode <= 2661) ||
      (2665 <= metadata.opcode && metadata.opcode <= 2675) ||
      (6066 <= metadata.opcode && metadata.opcode <= 6068)) {
    isDivideOrSqrt_ = true;
  }

  // Identify multiply operations
  if ((433 <= metadata.opcode && metadata.opcode <= 447) ||  // all MUL variants
      (759 <= metadata.opcode && metadata.opcode <= 762) ||
      (816 <= metadata.opcode && metadata.opcode <= 819) ||
      (915 <= metadata.opcode && metadata.opcode <= 918) ||
      (2436 <= metadata.opcode && metadata.opcode <= 2482) ||
      (2512 <= metadata.opcode && metadata.opcode <= 2514) ||
      (2702 <= metadata.opcode && metadata.opcode <= 2704) ||
      (3692 <= metadata.opcode && metadata.opcode <= 3716) ||
      (3793 <= metadata.opcode && metadata.opcode <= 3805) ||
      (4352 <= metadata.opcode && metadata.opcode <= 4380) ||
      (4503 <= metadata.opcode && metadata.opcode <= 4543) ||
      (4625 <= metadata.opcode && metadata.opcode <= 4643) ||
      (5804 <= metadata.opcode && metadata.opcode <= 5832) ||
      (2211 <= metadata.opcode &&
       metadata.opcode <= 2216) ||  // all MADD/MAD variants
      (2494 <= metadata.opcode && metadata.opcode <= 2499) ||
      (2699 <= metadata.opcode && metadata.opcode <= 2701) ||
      (3610 <= metadata.opcode && metadata.opcode <= 3615) ||
      (4227 == metadata.opcode) || (5682 == metadata.opcode) ||
      (2433 <= metadata.opcode &&
       metadata.opcode <= 2435) ||  // all MSUB variants
      (2509 <= metadata.opcode && metadata.opcode <= 2511) ||
      (3690 <= metadata.opcode && metadata.opcode <= 3691) ||
      (4351 == metadata.opcode) || (5803 == metadata.opcode) ||
      (424 <= metadata.opcode && metadata.opcode <= 426) ||  // all MLA variants
      (451 <= metadata.opcode && metadata.opcode <= 453) ||
      (1151 <= metadata.opcode && metadata.opcode <= 1160) ||
      (1378 <= metadata.opcode && metadata.opcode <= 1383) ||
      (1914 <= metadata.opcode && metadata.opcode <= 1926) ||
      (2341 <= metadata.opcode && metadata.opcode <= 2371) ||
      (2403 <= metadata.opcode && metadata.opcode <= 2404) ||
      (2500 <= metadata.opcode && metadata.opcode <= 2502) ||
      (3618 <= metadata.opcode && metadata.opcode <= 3634) ||
      (4295 <= metadata.opcode && metadata.opcode <= 4314) ||
      (4335 <= metadata.opcode && metadata.opcode <= 4336) ||
      (4453 <= metadata.opcode && metadata.opcode <= 4477) ||
      (4581 <= metadata.opcode && metadata.opcode <= 4605) ||
      (5749 <= metadata.opcode && metadata.opcode <= 5768) ||
      (5789 <= metadata.opcode && metadata.opcode <= 5790) ||
      (6115 <= metadata.opcode && metadata.opcode <= 6116) ||
      (427 <= metadata.opcode && metadata.opcode <= 429) ||  // all MLS variants
      (454 <= metadata.opcode && metadata.opcode <= 456) ||
      (2372 <= metadata.opcode && metadata.opcode <= 2402) ||
      (2503 <= metadata.opcode && metadata.opcode <= 2505) ||
      (3635 <= metadata.opcode && metadata.opcode <= 3651) ||
      (4315 <= metadata.opcode && metadata.opcode <= 4334) ||
      (4478 <= metadata.opcode && metadata.opcode <= 4502) ||
      (4606 <= metadata.opcode && metadata.opcode <= 4624) ||
      (5769 <= metadata.opcode && metadata.opcode <= 5788) ||
      (2430 <= metadata.opcode &&
       metadata.opcode <= 2432) ||  // all MSB variants
      (2506 <= metadata.opcode && metadata.opcode <= 2508) ||
      (3682 <= metadata.opcode && metadata.opcode <= 3685)) {
    isMultiply_ = true;
  }

  // Catch exceptions to the above identifier assignments
  // Uncaught preciate assignment due to lacking destination register
  if (metadata.opcode == Opcode::AArch64_PTEST_PP) {
    isPredicate_ = true;
  }
  // Uncaught float data assignment for FMOV move to general instructions
  if (((430 <= metadata.opcode && metadata.opcode <= 432) ||
       (2409 <= metadata.opcode && metadata.opcode <= 2429)) &&
      !(isScalarData_ || isVectorData_)) {
    isScalarData_ = true;
  }
  // Uncaught vector data assignment for SMOV and UMOV instructions
  if ((4341 <= metadata.opcode && metadata.opcode <= 4350) ||
      (5795 <= metadata.opcode && metadata.opcode <= 5802)) {
    isVectorData_ = true;
  }
  // Uncaught float data assignment for FCVT convert to general instructions
  if ((1976 <= metadata.opcode && metadata.opcode <= 2186) &&
      !(isScalarData_ || isVectorData_)) {
    isScalarData_ = true;
  }
}

void Instruction::nyi() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::EncodingNotYetImplemented;
}
void Instruction::unallocated() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::EncodingUnallocated;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng