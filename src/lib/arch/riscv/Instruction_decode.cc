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

  if (RISCV_REG_X31 >= reg && reg >= RISCV_REG_X1) {
    // Capstone produces 1 indexed register operands
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

/******************
 * DECODING LOGIC
 *****************/
void Instruction::decode() {
  if (metadata.id == RISCV_INS_INVALID) {
    exception_ = InstructionException::EncodingUnallocated;
    exceptionEncountered_ = true;
    return;
  }

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
    case Opcode::RISCV_LR_D:
    case Opcode::RISCV_LR_D_AQ:
    case Opcode::RISCV_LR_D_RL:
    case Opcode::RISCV_LR_D_AQ_RL:
    case Opcode::RISCV_LR_W:
    case Opcode::RISCV_LR_W_AQ:
    case Opcode::RISCV_LR_W_RL:
    case Opcode::RISCV_LR_W_AQ_RL:
      isAtomic_ = true;
    case Opcode::RISCV_LB:
    case Opcode::RISCV_LBU:
    case Opcode::RISCV_LH:
    case Opcode::RISCV_LHU:
    case Opcode::RISCV_LW:
    case Opcode::RISCV_LWU:
    case Opcode::RISCV_LD:
      isLoad_ = true;
      break;
    case Opcode::RISCV_SC_D:
    case Opcode::RISCV_SC_D_AQ:
    case Opcode::RISCV_SC_D_RL:
    case Opcode::RISCV_SC_D_AQ_RL:
    case Opcode::RISCV_SC_W:
    case Opcode::RISCV_SC_W_AQ:
    case Opcode::RISCV_SC_W_RL:
    case Opcode::RISCV_SC_W_AQ_RL:
      isAtomic_ = true;
    case Opcode::RISCV_SB:
    case Opcode::RISCV_SW:
    case Opcode::RISCV_SH:
    case Opcode::RISCV_SD:
      isStore_ = true;
      break;
  }

  if (Opcode::RISCV_AMOADD_D <= metadata.opcode &&
      metadata.opcode <= Opcode::RISCV_AMOXOR_W_RL) {
    // Atomics: both load and store
    isLoad_ = true;
    isStore_ = true;
    isAtomic_ = true;
  }

  bool accessesMemory = false;

  // Extract explicit register accesses
  for (size_t i = 0; i < metadata.operandCount; i++) {
    const auto& op = metadata.operands[i];

    if (i == 0 && op.type == RISCV_OP_REG) {
      // First operand
      if ((isBranch() && metadata.opcode != Opcode::RISCV_JAL &&
           metadata.opcode != Opcode::RISCV_JALR) ||
          (isStore() && !isAtomic())) {
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
        if (csRegToRegister(op.reg) != Instruction::ZERO_REGISTER) {
          destinationRegisters[destinationRegisterCount] =
              csRegToRegister(op.reg);

          destinationRegisterCount++;
        }
      }
    }

    else if (i > 0 && op.type == RISCV_OP_REG) {
      // Second or third operand
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);

      if (sourceRegisters[sourceRegisterCount] == Instruction::ZERO_REGISTER) {
        // Catch zero register references and pre-complete those operands
        operands[sourceRegisterCount] = RegisterValue(0, 8);
      } else {
        operandsPending++;
      }

      sourceRegisterCount++;
    }

    else if (i > 0 && op.type == RISCV_OP_MEM) {
      // Memory operand
      accessesMemory = true;
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.base);
      sourceRegisterCount++;
      operandsPending++;
    }
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

}  // namespace riscv
}  // namespace arch
}  // namespace simeng