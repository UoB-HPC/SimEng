#include "A64Instruction.hh"

namespace simeng {

std::vector<std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case A64Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    default:
      exception = A64InstructionException::ExecutionNotYetImplemented;
      return {};
  }
  return memoryAddresses;
}

}  // namespace simeng
