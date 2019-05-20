#include "A64Instruction.hh"
#include "A64InstructionMetadata.hh"

#include <iostream>

namespace simeng {

span<const std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case A64Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case A64Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case A64Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case A64Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
      if (metadata.operands[1].shift.type != 0) {
        executionNYI();
        return getGeneratedAddresses();
      }
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + operands[1].get<uint64_t>(), 8}});
      break;
    }
    case A64Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 2}});
      break;
    }
    case A64Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
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
    case A64Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
      break;
    }
    case A64Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8}});
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
    case A64Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case A64Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      // TODO: Implement prefetching
      break;
    }
    case A64Opcode::AArch64_STLXRW: {  // stlxr ws, wt, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    case A64Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case A64Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      uint64_t base = operands[2].get<uint64_t>();
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case A64Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case A64Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 16}});
      break;
    }
    case A64Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
      break;
    }
    case A64Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8}});
      break;
    }
    case A64Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    default:
      exception = A64InstructionException::ExecutionNotYetImplemented;
  }
  return getGeneratedAddresses();
}

}  // namespace simeng
