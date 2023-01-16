#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

/********************
 * HELPER FUNCTIONS
 *******************/

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

/** Invalidate instructions that are currently not yet implemented. This
 prevents errors during speculated branches with unknown destinations;
 non-executable assertions. memory is decoded into valid but not implemented
 instructions tripping assertions.
 TODO remove once all extensions are supported*/
void Instruction::invalidateIfNotImplemented() {
  if (metadata.opcode >= Opcode::RISCV_ADD &&
      metadata.opcode <= Opcode::RISCV_BNE)
    return;
  if (metadata.opcode >= Opcode::RISCV_DIV &&
      metadata.opcode <= Opcode::RISCV_ECALL)
    return;
  if (metadata.opcode >= Opcode::RISCV_JAL &&
      metadata.opcode <= Opcode::RISCV_SD)
    return;
  if (metadata.opcode >= Opcode::RISCV_SH &&
      metadata.opcode <= Opcode::RISCV_SRAW)
    return;
  if (metadata.opcode >= Opcode::RISCV_SRL &&
      metadata.opcode <= Opcode::RISCV_SW)
    return;
  if (metadata.opcode >= Opcode::RISCV_XOR &&
      metadata.opcode <= Opcode::RISCV_XORI)
    return;
  if (metadata.opcode == Opcode::RISCV_FENCE) return;

  exception_ = InstructionException::EncodingUnallocated;
  exceptionEncountered_ = true;
  return;
}

/******************
 * DECODING LOGIC
 *****************/
void Instruction::decode() {
  invalidateIfNotImplemented();
  if (exceptionEncountered_) return;
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
      [[fallthrough]];
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
      [[fallthrough]];
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

  // Extract explicit register accesses, ignore immediates until execute
  for (size_t i = 0; i < metadata.operandCount; i++) {
    const auto& op = metadata.operands[i];

    // First operand is always of REG type but could be either source or
    // destination
    if (i == 0 && op.type == RISCV_OP_REG) {
      // If opcode is branch or store (but not atomic or jump) the first operand
      // is a source register, for all other instructions the first operand is a
      // destination register
      if ((isBranch() && metadata.opcode != Opcode::RISCV_JAL &&
           metadata.opcode != Opcode::RISCV_JALR) ||
          (isStoreAddress() && !isAtomic())) {
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
        } else {
          /**
           * Register writes to x0 are discarded so no destination register is
           * set.
           *
           * While the execution stage may still write to the results array,
           * when Instruction::getResults and
           * Instruction::getDestinationRegisters are called during writeback,
           * zero sized spans are returned (determined by the value of
           * destinationRegisterCount). This in turn means no register update is
           * performed.
           *
           * TODO this will break if there are more than 2 destination registers
           * with one being the zero register e.g. if an instruction implicitly
           * writes to a system register. The current implementation could mean
           * that the second result is discarded
           *
           */
        }
      }
    }

    // For all instructions, every register operand after the first is a source
    // register
    else if (i > 0 && op.type == RISCV_OP_REG) {
      //  Second or third operand
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);

      if (sourceRegisters[sourceRegisterCount] == Instruction::ZERO_REGISTER) {
        // Catch zero register references and pre-complete those operands
        operands[sourceRegisterCount] = RegisterValue(0, 8);
      } else {
        operandsPending++;
      }

      sourceRegisterCount++;
    }

    // First operand is never MEM type, only check after the first. If register
    // contains memory address, extract reg number from capstone object
    else if (i > 0 && op.type == RISCV_OP_MEM) {
      //  Memory operand
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.mem.base);
      sourceRegisterCount++;
      operandsPending++;
    }
  }

  if ((Opcode::RISCV_SLL <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_SLLW) ||
      (Opcode::RISCV_SRA <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_SRAW) ||
      (Opcode::RISCV_SRL <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_SRLW)) {
    // Shift instructions
    isShift_ = true;
  }

  if ((Opcode::RISCV_XOR <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_XORI) ||
      (Opcode::RISCV_OR <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_ORI) ||
      (Opcode::RISCV_AND <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_ANDI)) {
    // Logical instructions
    isLogical_ = true;
  }

  if ((Opcode::RISCV_SLT <= metadata.opcode &&
       metadata.opcode <= Opcode::RISCV_SLTU)) {
    // Compare instructions
    isCompare_ = true;
  }

  // Set branch type
  switch (metadata.opcode) {
    case Opcode::RISCV_BEQ:
    case Opcode::RISCV_BNE:
    case Opcode::RISCV_BLT:
    case Opcode::RISCV_BLTU:
    case Opcode::RISCV_BGE:
    case Opcode::RISCV_BGEU:
      branchType_ = BranchType::Conditional;
      knownTarget_ = instructionAddress_ + metadata.operands[2].imm;
      break;
    case Opcode::RISCV_JAL:
    case Opcode::RISCV_JALR:
      branchType_ = BranchType::Unconditional;
      knownTarget_ = instructionAddress_ + metadata.operands[1].imm;
      break;
  }
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng