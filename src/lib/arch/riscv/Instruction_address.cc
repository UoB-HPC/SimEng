#include <cmath>

#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

span<const MemoryAccessTarget> Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  uint64_t address = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;

  switch (metadata.opcode) {
    case Opcode::RISCV_LD: {
      setMemoryAddresses({{address, 8}});
      break;
    }
    case Opcode::RISCV_LW:
    case Opcode::RISCV_LWU: {
      setMemoryAddresses({{address, 4}});
      break;
    }
    case Opcode::RISCV_LH:
    case Opcode::RISCV_LHU: {
      setMemoryAddresses({{address, 2}});
      break;
    }
    case Opcode::RISCV_LB:
    case Opcode::RISCV_LBU: {
      setMemoryAddresses({{address, 1}});
      break;
    }
    default:
      exceptionEncountered_ = true;
      exception_ = InstructionException::ExecutionNotYetImplemented;
      break;
  }
  return getGeneratedAddresses();
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng