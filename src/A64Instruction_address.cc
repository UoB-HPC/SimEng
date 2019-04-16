#include "A64Instruction.hh"
#include "A64InstructionMetadata.hh"

namespace simeng {

span<const std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case A64Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
      if (metadata.operands[1].shift.type != 0) {
        executionNYI();
        return getGeneratedAddresses();
      }
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + operands[1].get<uint64_t>(), 8}});
    }
    case A64Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      setMemoryAddresses({{metadata.operands[1].imm + instructionAddress_, 8}});
      break;
    }
    case A64Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[0].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case A64Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
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
  }
  return getGeneratedAddresses();
}

}  // namespace simeng
