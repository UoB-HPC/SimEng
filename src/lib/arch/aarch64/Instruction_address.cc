#include "simeng/arch/aarch64/Instruction.hh"

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

span<const MemoryAccessTarget> Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_LDAXRX: {  // ldaxr xd, [xn]
      setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_LDRBBpost: {  // ldrb wt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 1}});
      break;
    }
    case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_LDRBBroW: {  // ldrb wt,
                                      //  [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 1}});
      break;
    }
    case Opcode::AArch64_LDRBBroX: {  // ldrb wt,
                                      //  [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 1}});
      break;
    }
    case Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
      if (metadata.operands[1].shift.type != 0) {
        executionNYI();
        return getGeneratedAddresses();
      }
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + operands[1].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_LDRDui: {  // ldr dt, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 2}});
      break;
    }
    case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm, {extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm, {extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 16}});
      break;
    }
    case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 16}});
      break;
    }
    case Opcode::AArch64_LDRSpost: {  // ldr st, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_LDRSpre: {  // ldr st, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm, {extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
      break;
    }
    case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm, {extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
      break;
    }
    case Opcode::AArch64_LDRSui: {  // ldr st, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      setMemoryAddresses({{metadata.operands[1].imm + instructionAddress_, 8}});
      break;
    }
    case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8}});
      break;
    }
    case Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[0].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case Opcode::AArch64_LDPSi: {  // ldp st1, st2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4}, {base + 4, 4}});
      break;
    }
    case Opcode::AArch64_LDPWi: {  // ldp wt1, wt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4}, {base + 4, 4}});
      break;
    }
    case Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm]!
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      setMemoryAddresses({{base, 4}});
      break;
    }
    case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 16}});
      break;
    }
    case Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      // TODO: Implement prefetching
      break;
    }
    case Opcode::AArch64_STLXRW: {  // stlxr ws, wt, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_STLXRX: {  // stlxr ws, xt, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_STPDi: {  // stp dt1, dt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      uint64_t base = operands[2].get<uint64_t>();
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case Opcode::AArch64_STPWi: {  // stp wt1, wt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4}, {base + 4, 4}});
      break;
    }
    case Opcode::AArch64_STRBBpost: {  // strb wd, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 1}});
      break;
    }
    case Opcode::AArch64_STRBBpre: {  // strb wd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_STRBBroW: {  // strb wd,
                                      //  [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 1}});
      break;
    }
    case Opcode::AArch64_STRBBroX: {  // strb wd,
                                      //  [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 1}});
      break;
    }
    case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 2}});
      break;
    }
    case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_STRHHroW: {  // strh wd,
                                      //  [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_STRHHroX: {  // strh wd,
                                      //  [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_STRQpost: {  // str qt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
      break;
    }
    case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 16}});
      break;
    }
    case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 16}});
      break;
    }
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
      break;
    }
    case Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
      break;
    }
    case Opcode::AArch64_STRXpre: {  // str xd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_STRXroW: {  // str xd, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8}});
      break;
    }
    case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8}});
      break;
    }
    case Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_STURXi: {  // stur xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    default:
      exception = InstructionException::ExecutionNotYetImplemented;
  }
  return getGeneratedAddresses();
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
