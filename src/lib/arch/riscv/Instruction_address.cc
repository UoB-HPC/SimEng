#include <cmath>

#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

span<const memory::MemoryAccessTarget> Instruction::generateAddresses() {
  assert(
      (isInstruction(InsnType::isLoad) || isInstruction(InsnType::isStore)) &&
      "generateAddresses called on non-load-or-store instruction");

  uint64_t address;
  if (isInstruction(InsnType::isLoad) && isInstruction(InsnType::isStore) &&
      isInstruction(InsnType::isAtomic)) {
    // Atomics
    // Metadata operands[2] corresponds to instruction sourceRegValues[1]
    assert(metadata_.operands[2].type == RISCV_OP_MEM &&
           "metadata_ operand not of correct type during RISC-V address "
           "generation");
    address = sourceValues_[1].get<uint64_t>();
  } else if (isInstruction(InsnType::isLoad) &&
             isInstruction(InsnType::isAtomic)) {
    // Load reserved
    // Metadata operands[1] corresponds to instruction sourceRegValues[0]
    assert(metadata_.operands[1].type == RISCV_OP_MEM &&
           "metadata_ operand not of correct type during RISC-V address "
           "generation");
    address = sourceValues_[0].get<uint64_t>();
  } else if (isInstruction(InsnType::isStore) &&
             isInstruction(InsnType::isAtomic)) {
    // Store conditional
    assert(metadata_.operands[2].type == RISCV_OP_MEM &&
           "metadata_ operand not of correct type during RISC-V address "
           "generation");
    address = sourceValues_[1].get<uint64_t>();
  } else if (isInstruction(InsnType::isLoad)) {
    assert(metadata_.operands[1].type == RISCV_OP_MEM &&
           "metadata_ operand not of correct type during RISC-V address "
           "generation");
    address = sourceValues_[0].get<uint64_t>() + sourceImm_;
  } else {
    assert((metadata_.operands[1].type == RISCV_OP_MEM) &&
           "metadata_ operand not of correct type during RISC-V address "
           "generation");

    address = sourceValues_[1].get<uint64_t>() + sourceImm_;
  }

  // Atomics
  if (Opcode::RISCV_AMOADD_D <= metadata_.opcode &&
      metadata_.opcode <= Opcode::RISCV_AMOXOR_W_RL) {  // Atomics
    // THIS IS DEPENDENT ON CAPSTONE ENCODING AND COULD BREAK IF CHANGED
    int size = ((metadata_.opcode - 182) / 4) % 2;  // 1 = Word, 0 = Double
    if (size == 1) {
      // Word
      setMemoryAddresses({{address, 4}});
    } else {
      // Double
      setMemoryAddresses({{address, 8}});
    }
    return getGeneratedAddresses();
  }

  switch (metadata_.opcode) {
    case Opcode::RISCV_SD:
      [[fallthrough]];
    case Opcode::RISCV_LD:
      [[fallthrough]];
    case Opcode::RISCV_FSD:
      [[fallthrough]];
    case Opcode::RISCV_FLD: {
      setMemoryAddresses({{address, 8}});
      break;
    }
    case Opcode::RISCV_SW:
      [[fallthrough]];
    case Opcode::RISCV_LW:
      [[fallthrough]];
    case Opcode::RISCV_LWU:
      [[fallthrough]];
    case Opcode::RISCV_FSW:
      [[fallthrough]];
    case Opcode::RISCV_FLW: {
      setMemoryAddresses({{address, 4}});
      break;
    }
    case Opcode::RISCV_SH:
      [[fallthrough]];
    case Opcode::RISCV_LH:
      [[fallthrough]];
    case Opcode::RISCV_LHU: {
      setMemoryAddresses({{address, 2}});
      break;
    }
    case Opcode::RISCV_SB:
      [[fallthrough]];
    case Opcode::RISCV_LB:
      [[fallthrough]];
    case Opcode::RISCV_LBU: {
      setMemoryAddresses({{address, 1}});
      break;
    }

    // Atomics
    case Opcode::RISCV_LR_W:
      [[fallthrough]];
    case Opcode::RISCV_LR_W_AQ:
      [[fallthrough]];
    case Opcode::RISCV_LR_W_RL:
      [[fallthrough]];
    case Opcode::RISCV_LR_W_AQ_RL: {
      setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::RISCV_LR_D:
      [[fallthrough]];
    case Opcode::RISCV_LR_D_AQ:
      [[fallthrough]];
    case Opcode::RISCV_LR_D_RL:
      [[fallthrough]];
    case Opcode::RISCV_LR_D_AQ_RL: {
      setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::RISCV_SC_W:
      [[fallthrough]];
    case Opcode::RISCV_SC_W_AQ:
      [[fallthrough]];
    case Opcode::RISCV_SC_W_RL:
      [[fallthrough]];
    case Opcode::RISCV_SC_W_AQ_RL: {
      setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::RISCV_SC_D:
      [[fallthrough]];
    case Opcode::RISCV_SC_D_AQ:
      [[fallthrough]];
    case Opcode::RISCV_SC_D_RL:
      [[fallthrough]];
    case Opcode::RISCV_SC_D_AQ_RL: {
      setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
      break;
    }
    default:
      exceptionEncountered_ = true;
      exception_ = InstructionException::ExecutionNotYetImplemented;
      break;
  }
  return getGeneratedAddresses();
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng