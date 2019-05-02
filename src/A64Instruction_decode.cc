#include "A64Instruction.hh"
#include "A64InstructionMetadata.hh"

#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {

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
constexpr Register genReg(uint16_t tag) {
  return {A64RegisterType::GENERAL, tag};
}
// Generate a NZCV register identifier
constexpr Register nzcvReg() { return {A64RegisterType::NZCV, 0}; }

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
    return {A64RegisterType::VECTOR, static_cast<uint16_t>(reg - ARM64_REG_V0)};
  }

  // ARM64_REG_X0 -> +31 are 64-bit (X) registers, reading from the general
  // file
  if (reg >= ARM64_REG_X0) {
    return {A64RegisterType::GENERAL,
            static_cast<uint16_t>(reg - ARM64_REG_X0)};
  }

  // ARM64_REG_W0 -> +30 are 32-bit (W) registers, reading from the general
  // file. Excludes #31 (WZR/WSP).
  if (reg >= ARM64_REG_W0) {
    return {A64RegisterType::GENERAL,
            static_cast<uint16_t>(reg - ARM64_REG_W0)};
  }

  // ARM64_REG_B0 and above are repeated ranges representing scalar access
  // specifiers on the vector registers (i.e., B, H, S, D, Q), each covering 32
  // registers
  if (reg >= ARM64_REG_B0) {
    return {A64RegisterType::VECTOR,
            static_cast<uint16_t>((reg - ARM64_REG_B0) % 32)};
  }

  // ARM64_REG_WZR and _XZR are zero registers, and don't read
  if (reg == ARM64_REG_WZR || reg == ARM64_REG_XZR) {
    return A64Instruction::ZERO_REGISTER;
  }

  // ARM64_REG_SP and _WSP are stack pointer registers, stored in r31 of the
  // general file
  if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) {
    return {A64RegisterType::GENERAL, 31};
  }

  // ARM64_REG_NZCV is the condition flags register
  if (reg == ARM64_REG_NZCV) {
    return {A64RegisterType::NZCV, 0};
  }
  // ARM64_REG_X29 is the frame pointer, stored in r29 of the general file
  if (reg == ARM64_REG_X29) {
    return {A64RegisterType::GENERAL, 29};
  }
  // ARM64_REG_X30 is the link register, stored in r30 of the general file
  if (reg == ARM64_REG_X30) {
    return {A64RegisterType::GENERAL, 30};
  }

  assert(false && "Decoding failed due to unknown register identifier");
  return {std::numeric_limits<uint8_t>::max(),
          std::numeric_limits<uint16_t>::max()};
}

// Check for and mark WZR/XZR references
const Register& filterZR(const Register& reg) {
  return (reg.type == A64RegisterType::GENERAL && reg.tag == 31
              ? A64Instruction::ZERO_REGISTER
              : reg);
}

/******************
 * DECODING LOGIC
 *****************/
void A64Instruction::decode() {
  if (metadata.id == ARM64_INS_INVALID) {
    exception = A64InstructionException::EncodingUnallocated;
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
        destinationRegisterCount++;
      }
      if (op.access & cs_ac_type::CS_AC_READ) {
        // Add register reads to destinations
        sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);
        if (sourceRegisters[sourceRegisterCount] ==
            A64Instruction::ZERO_REGISTER) {
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
    }
  }

  // Identify branches
  for (size_t i = 0; i < metadata.groupCount; i++) {
    if (metadata.groups[i] == ARM64_GRP_JUMP) {
      isBranch_ = true;
    }
  }
  // Identify loads/stores
  if (accessesMemory) {
    // Check first operand access to determine if it's a load or store
    if (metadata.operands[0].access == CS_AC_WRITE) {
      isLoad_ = true;
    } else {
      isStore_ = true;
    }
  }
  if (metadata.opcode == A64Opcode::AArch64_LDRXl ||
      metadata.opcode == A64Opcode::AArch64_LDRSWl) {
    // Literal loads aren't flagged as having a memory operand, so these must be
    // marked as loads manually
    isLoad_ = true;
  }
}

void A64Instruction::nyi() {
  exceptionEncountered_ = true;
  exception = A64InstructionException::EncodingNotYetImplemented;
}
void A64Instruction::unallocated() {
  exceptionEncountered_ = true;
  exception = A64InstructionException::EncodingUnallocated;
}

}  // namespace simeng
