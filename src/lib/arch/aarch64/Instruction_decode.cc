#include "InstructionMetadata.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

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
  uint32_t mask = (-1) << currentLength;
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
    sourceRegisterCount++;
    operandsPending++;
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
        if (destinationRegisters[destinationRegisterCount].type ==
            RegisterType::VECTOR) {
          isASIMD_ = true;
        }
        if (destinationRegisters[destinationRegisterCount].type ==
            RegisterType::PREDICATE) {
          isPredicate_ = true;
          if (metadata.id == ARM64_INS_FCMGE ||
              metadata.id == ARM64_INS_FCMGT ||
              metadata.id == ARM64_INS_FCMLT ||
              metadata.opcode == Opcode::AArch64_LDR_PXI ||
              metadata.opcode == Opcode::AArch64_STR_PXI) {
            isPredicate_ = false;
          }
        }

        destinationRegisterCount++;
      }
      if (op.access & cs_ac_type::CS_AC_READ) {
        // Add register reads to destinations
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);
        if (sourceRegisters[sourceRegisterCount].type == RegisterType::VECTOR) {
          isASIMD_ = true;
        }

        if (sourceRegisters[sourceRegisterCount] ==
            Instruction::ZERO_REGISTER) {
          // Catch zero register references and pre-complete those operands
          operands[sourceRegisterCount] = RegisterValue(0, 8);
        } else {
          operandsPending++;
        }
        sourceRegisterCount++;
      }
    } else if (op.type == ARM64_OP_MEM) {  // Memory operand
      accessesMemory = true;
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.base);
      sourceRegisterCount++;
      operandsPending++;

      if (metadata.writeback) {
        // Writeback instructions modify the base address
        destinationRegisters[destinationRegisterCount] =
            csRegToRegister(op.mem.base);
        destinationRegisterCount++;
      }
      if (op.mem.index) {
        // Register offset; add to sources
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.index);
        sourceRegisterCount++;
        operandsPending++;
      }
    } else if (op.type == ARM64_OP_REG_MRS) {
      sourceRegisters[sourceRegisterCount] = {
          RegisterType::SYSTEM, architecture_.getSystemRegisterTag(op.imm)};
      sourceRegisterCount++;
      operandsPending++;
    } else if (op.type == ARM64_OP_REG_MSR) {
      destinationRegisters[destinationRegisterCount] = {
          RegisterType::SYSTEM, architecture_.getSystemRegisterTag(op.imm)};
      destinationRegisterCount++;
    }

    if (op.shift.value > 0) isShift_ = true;  // Identify shift operations
  }

  if (metadata.setsFlags) isShift_ = true;

  // Identify branches
  for (size_t i = 0; i < metadata.groupCount; i++) {
    if (metadata.groups[i] == ARM64_GRP_JUMP) {
      isBranch_ = true;
    }
  }
  // Identify loads/stores
  if (accessesMemory) {
    // Check first operand access to determine if it's a load or store
    if (metadata.operands[0].access & CS_AC_WRITE) {
      if (metadata.id == ARM64_INS_STXR || metadata.id == ARM64_INS_STLXR) {
        // Exceptions to this is load condition are exclusive store with a
        // success flag as first operand
        isStore_ = true;
      } else {
        isLoad_ = true;
      }
    } else {
      isStore_ = true;
    }
  }
  if (metadata.opcode == Opcode::AArch64_LDRXl ||
      metadata.opcode == Opcode::AArch64_LDRSWl) {
    // Literal loads aren't flagged as having a memory operand, so these must be
    // marked as loads manually
    isLoad_ = true;
  }
  if ((1189 < metadata.opcode && metadata.opcode < 1204) ||
      (1605 < metadata.opcode && metadata.opcode < 1617) ||
      (2906 < metadata.opcode && metadata.opcode < 2913) ||
      (4045 < metadata.opcode && metadata.opcode < 4052)) {
    isDivide_ = true;
  }
  if ((1210 < metadata.opcode && metadata.opcode < 1214) ||
      (1328 < metadata.opcode && metadata.opcode < 1367) ||
      (1393 < metadata.opcode && metadata.opcode < 1444) ||
      (1454 < metadata.opcode && metadata.opcode < 1458) ||
      (1469 < metadata.opcode && metadata.opcode < 1476) ||
      (2502 < metadata.opcode && metadata.opcode < 2505) ||
      (2578 < metadata.opcode && metadata.opcode < 2599) ||
      (2992 == metadata.opcode) ||
      (3076 < metadata.opcode && metadata.opcode < 3093) ||
      (3148 < metadata.opcode && metadata.opcode < 3197) ||
      (4072 == metadata.opcode) ||
      (4154 < metadata.opcode && metadata.opcode < 4171)) {
    isMultiply_ = true;
  }
  if (metadata.opcode == 2756) {
    isRET_ = true;
  }
  if (metadata.opcode == 325 || metadata.opcode == 326) {
    isBL_ = true;
  }
  if (metadata.id == ARM64_INS_PTEST) {
    isPredicate_ = true;
  }
  if (metadata.id == ARM64_INS_ADDVL || metadata.id == ARM64_INS_FDUP ||
      metadata.id == ARM64_INS_FMSB || metadata.id == ARM64_INS_LD1B ||
      metadata.id == ARM64_INS_LD1RD || metadata.id == ARM64_INS_LD1RW ||
      metadata.id == ARM64_INS_LD1D || metadata.id == ARM64_INS_LD1W ||
      metadata.id == ARM64_INS_MOVPRFX || metadata.id == ARM64_INS_PTEST ||
      metadata.id == ARM64_INS_PTRUE || metadata.id == ARM64_INS_ST1B ||
      metadata.id == ARM64_INS_ST1D || metadata.id == ARM64_INS_ST1W ||
      metadata.id == ARM64_INS_PUNPKHI || metadata.id == ARM64_INS_PUNPKLO ||
      metadata.id == ARM64_INS_UZP1 || metadata.id == ARM64_INS_WHILELO ||
      (244 < metadata.opcode && metadata.opcode < 252) ||
      (705 < metadata.opcode && metadata.opcode < 720) ||
      (781 < metadata.opcode && metadata.opcode < 785) ||
      (825 < metadata.opcode && metadata.opcode < 838) ||
      (881 < metadata.opcode && metadata.opcode < 888) ||
      (903 < metadata.opcode && metadata.opcode < 910) ||
      (946 < metadata.opcode && metadata.opcode < 950) ||
      (1125 < metadata.opcode && metadata.opcode < 1133) ||
      (1195 < metadata.opcode && metadata.opcode < 1199) ||
      (1203 < metadata.opcode && metadata.opcode < 1207) ||
      (1213 < metadata.opcode && metadata.opcode < 1217) ||
      (1328 < metadata.opcode && metadata.opcode < 1335) ||
      (1347 < metadata.opcode && metadata.opcode < 1354) ||
      (1418 < metadata.opcode && metadata.opcode < 1431) ||
      (1446 < metadata.opcode && metadata.opcode < 1450) ||
      (1625 < metadata.opcode && metadata.opcode < 1635) ||
      (1608 < metadata.opcode && metadata.opcode < 1612) ||
      (2342 < metadata.opcode && metadata.opcode < 2345) ||
      (2466 < metadata.opcode && metadata.opcode < 2483) ||
      (metadata.opcode == 2648) ||
      (2920 < metadata.opcode && metadata.opcode < 2926) ||
      (3007 < metadata.opcode && metadata.opcode < 3016) ||
      (3037 < metadata.opcode && metadata.opcode < 3046) ||
      (3773 < metadata.opcode && metadata.opcode < 3776) ||
      (4484 < metadata.opcode && metadata.opcode < 4493) ||
      (4499 < metadata.opcode && metadata.opcode < 4508)) {
    isSVE_ = true;
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