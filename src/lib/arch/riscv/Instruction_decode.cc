#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {
namespace arch {
namespace riscv {

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

/** Parses the Capstone `riscv_reg` value to generate an architectural register
 * representation.
 *
 * WARNING: this conversion is FRAGILE, and relies on the structure of the
 * `riscv_reg` enum. Updates to the Capstone library version may cause this to
 * break. */
Register csRegToRegister(unsigned int reg) {
  // Check from top of the range downwards


  if (reg <= RISCV_REG_X31 &&  reg >= RISCV_REG_X1) {
    return {RegisterType::GENERAL, static_cast<uint16_t>(reg - 1)};
  }

  if (reg == RISCV_REG_X0) {
    // Zero register
    return Instruction::ZERO_REGISTER;
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
  if (metadata.id == RISCV_INS_INVALID) {
    exception_ = InstructionException::EncodingUnallocated;
    exceptionEncountered_ = true;
    return;
  }

//  // Extract implicit writes
//  for (size_t i = 0; i < metadata.implicitDestinationCount; i++) {
//    destinationRegisters[destinationRegisterCount] = csRegToRegister(
//        static_cast<arm64_reg>(metadata.implicitDestinations[i]));
//    destinationRegisterCount++;
//  }
//  // Extract implicit reads
//  for (size_t i = 0; i < metadata.implicitSourceCount; i++) {
//    sourceRegisters[sourceRegisterCount] =
//        csRegToRegister(static_cast<arm64_reg>(metadata.implicitSources[i]));
//    sourceRegisterCount++;
//    operandsPending++;
//  }


  // Identify branches
  switch (metadata.opcode) {
    case Opcode::RISCV_BEQ:
    case Opcode::RISCV_BNE:
    case Opcode::RISCV_BLT:
    case Opcode::RISCV_BLTU:
    case Opcode::RISCV_BGE:
    case Opcode::RISCV_BGEU:
    case Opcode::RISCV_JAL:
    case Opcode::RISCV_JALR:
      isBranch_ = true;
      break;
  // Identify loads/stores
    case Opcode::RISCV_LB:
    case Opcode::RISCV_LBU:
    case Opcode::RISCV_LH:
    case Opcode::RISCV_LHU:
    case Opcode::RISCV_LW:
    case Opcode::RISCV_LWU:
    case Opcode::RISCV_LD:
      isLoad_ = true;
      break;
    case Opcode::RISCV_SB:
    case Opcode::RISCV_SW:
    case Opcode::RISCV_SH:
    case Opcode::RISCV_SD:
      isStore_ = true;
      break;
  }


  bool accessesMemory = false;

  // Extract explicit register accesses
  for (size_t i = 0; i < metadata.operandCount; i++) {
    const auto& op = metadata.operands[i];

    // Capstone produces 1 indexed register operands
    if (i == 0 && op.type == RISCV_OP_REG) {

      if ((isBranch() && metadata.opcode != Opcode::RISCV_JAL &&  metadata.opcode != Opcode::RISCV_JALR) || isStore()) {
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);

        if (sourceRegisters[sourceRegisterCount] ==
            Instruction::ZERO_REGISTER) {
          // Catch zero register references and pre-complete those operands
          operands[sourceRegisterCount] = RegisterValue(0, 8);
        } else {
          operandsPending++;
        }

        sourceRegisterCount++;
      } else {
          destinationRegisters[destinationRegisterCount] =
              csRegToRegister(op.reg);

          destinationRegisterCount++;
      }
    }

    if (i > 0 && op.type == RISCV_OP_REG) {
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);

      if (sourceRegisters[sourceRegisterCount] == Instruction::ZERO_REGISTER) {
        // Catch zero register references and pre-complete those operands
        operands[sourceRegisterCount] = RegisterValue(0, 8);
      } else {
        operandsPending++;
      }

      sourceRegisterCount++;
    }

//    if (i > 0 && op.type == RISCV_OP_REG) {  // Register operand
                                    //      // writes
                                    //      if ((op. ) && op.reg != 0) {
      //        // Add register writes to destinations, but skip zero-register
      //        // destinations
      //        destinationRegisters[destinationRegisterCount] =
      //            csRegToRegister(op.reg);
      //
      //        destinationRegisterCount++;
      //      }
      //      if (op.access & cs_ac_type::CS_AC_READ) {
      //        // Add register reads to destinations
      //        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);
      //        if (sourceRegisters[sourceRegisterCount].type == RegisterType::VECTOR) {
      //          isASIMD_ = true;
      //        }
      //
      //        if (sourceRegisters[sourceRegisterCount] ==
      //            Instruction::ZERO_REGISTER) {
      //          // Catch zero register references and pre-complete those operands operands[sourceRegisterCount] = RegisterValue(0, 8);
      //        } else {
      //          operandsPending++;
      //        }
      //        sourceRegisterCount++;
      //      }
    else if (i > 0 && op.type == RISCV_OP_MEM) {  // Memory operand
      accessesMemory = true;
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.base);
      sourceRegisterCount++;
      operandsPending++;
      //
      //      if (metadata.writeback) {
      //        // Writeback instructions modify the base address
      //        destinationRegisters[destinationRegisterCount] =
      //            csRegToRegister(op.mem.base);
      //        destinationRegisterCount++;
      //      }
      //      if (op.mem.index) {
      //        // Register offset; add to sources
      //        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.index); sourceRegisterCount++;
      //        operandsPending++;
      //      }
      //    } else if (op.type == ARM64_OP_REG_MRS) {
      //      sourceRegisters[sourceRegisterCount] = {
      //          RegisterType::SYSTEM, architecture_.getSystemRegisterTag(op.imm)};
      //      sourceRegisterCount++;
      //      operandsPending++;
      //    } else if (op.type == ARM64_OP_REG_MSR) {
      //      destinationRegisters[destinationRegisterCount] = {
      //          RegisterType::SYSTEM, architecture_.getSystemRegisterTag(op.imm)};
      //      destinationRegisterCount++;
      //    }
      //
      //    if (op.shift.value > 0) isShift_ = true;  // Identify shift operations
    }
  }


//  if (metadata.opcode == Opcode::AArch64_LDRXl ||
//      metadata.opcode == Opcode::AArch64_LDRSWl) {
//    // Literal loads aren't flagged as having a memory operand, so these must be
//    // marked as loads manually
//    isLoad_ = true;
//  }
//  if ((1189 < metadata.opcode && metadata.opcode < 1204) ||
//      (1605 < metadata.opcode && metadata.opcode < 1617) ||
//      (2906 < metadata.opcode && metadata.opcode < 2913) ||
//      (4045 < metadata.opcode && metadata.opcode < 4052)) {
//    isDivide_ = true;
//  }
//  if ((1210 < metadata.opcode && metadata.opcode < 1214) ||
//      (1328 < metadata.opcode && metadata.opcode < 1367) ||
//      (1393 < metadata.opcode && metadata.opcode < 1444) ||
//      (1454 < metadata.opcode && metadata.opcode < 1458) ||
//      (1469 < metadata.opcode && metadata.opcode < 1476) ||
//      (2502 < metadata.opcode && metadata.opcode < 2505) ||
//      (2578 < metadata.opcode && metadata.opcode < 2599) ||
//      (2992 == metadata.opcode) ||
//      (3076 < metadata.opcode && metadata.opcode < 3093) ||
//      (3148 < metadata.opcode && metadata.opcode < 3197) ||
//      (4072 == metadata.opcode) ||
//      (4154 < metadata.opcode && metadata.opcode < 4171)) {
//    isMultiply_ = true;
//  }
//  if (metadata.opcode == 2756) {
//    isRET_ = true;
//  }
//  if (metadata.opcode == 325 || metadata.opcode == 326) {
//    isBL_ = true;
//  }
//  if (metadata.id == ARM64_INS_PTEST) {
//    isPredicate_ = true;
//  }
//  if (metadata.id == ARM64_INS_ADDVL || metadata.id == ARM64_INS_FDUP ||
//      metadata.id == ARM64_INS_FMSB || metadata.id == ARM64_INS_LD1B ||
//      metadata.id == ARM64_INS_LD1RD || metadata.id == ARM64_INS_LD1RW ||
//      metadata.id == ARM64_INS_LD1D || metadata.id == ARM64_INS_LD1W ||
//      metadata.id == ARM64_INS_MOVPRFX || metadata.id == ARM64_INS_PTEST ||
//      metadata.id == ARM64_INS_PTRUE || metadata.id == ARM64_INS_ST1B ||
//      metadata.id == ARM64_INS_ST1D || metadata.id == ARM64_INS_ST1W ||
//      metadata.id == ARM64_INS_PUNPKHI || metadata.id == ARM64_INS_PUNPKLO ||
//      metadata.id == ARM64_INS_UZP1 || metadata.id == ARM64_INS_WHILELO ||
//      (244 < metadata.opcode && metadata.opcode < 252) ||
//      (705 < metadata.opcode && metadata.opcode < 720) ||
//      (781 < metadata.opcode && metadata.opcode < 785) ||
//      (825 < metadata.opcode && metadata.opcode < 838) ||
//      (881 < metadata.opcode && metadata.opcode < 888) ||
//      (903 < metadata.opcode && metadata.opcode < 910) ||
//      (946 < metadata.opcode && metadata.opcode < 950) ||
//      (1125 < metadata.opcode && metadata.opcode < 1133) ||
//      (1195 < metadata.opcode && metadata.opcode < 1199) ||
//      (1203 < metadata.opcode && metadata.opcode < 1207) ||
//      (1213 < metadata.opcode && metadata.opcode < 1217) ||
//      (1328 < metadata.opcode && metadata.opcode < 1335) ||
//      (1347 < metadata.opcode && metadata.opcode < 1354) ||
//      (1418 < metadata.opcode && metadata.opcode < 1431) ||
//      (1446 < metadata.opcode && metadata.opcode < 1450) ||
//      (1625 < metadata.opcode && metadata.opcode < 1635) ||
//      (1608 < metadata.opcode && metadata.opcode < 1612) ||
//      (2342 < metadata.opcode && metadata.opcode < 2345) ||
//      (2466 < metadata.opcode && metadata.opcode < 2483) ||
//      (metadata.opcode == 2648) ||
//      (2920 < metadata.opcode && metadata.opcode < 2926) ||
//      (3007 < metadata.opcode && metadata.opcode < 3016) ||
//      (3037 < metadata.opcode && metadata.opcode < 3046) ||
//      (3773 < metadata.opcode && metadata.opcode < 3776) ||
//      (4484 < metadata.opcode && metadata.opcode < 4493) ||
//      (4499 < metadata.opcode && metadata.opcode < 4508)) {
//    isSVE_ = true;
//  }
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