#include "simeng/arch/aarch64/Instruction.hh"

#include <cmath>
#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

span<const MemoryAccessTarget> Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case Opcode::AArch64_LD1RD_IMM: {  // ld1rd {zt.d}, pg/z, [xn, #imm]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          setMemoryAddresses(
              {{operands[1].get<uint64_t>() + metadata.operands[2].mem.disp, 8,
                0, 1}});
          break;
        }
      }
      break;
    }
    case Opcode::AArch64_LD1RW_IMM: {  // ld1rw {zt.s}, pg/z, [xn, #imm]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          setMemoryAddresses(
              {{operands[1].get<uint64_t>() + metadata.operands[2].mem.disp, 4,
                0, 1}});
          break;
        }
      }
      break;
    }
    case Opcode::AArch64_LD1Rv4s: {  // ld1r {vt.4s}, [xn]
      setMemoryAddresses({{operands[1].get<uint64_t>(), 16, 1}});
      break;
    }
    case Opcode::AArch64_LD1Rv4s_POST: {  // ld1r {vt.4s}, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 16, 1}});
      break;
    }
    case Opcode::AArch64_LD1Twov16b: {  // ld1 {vt1.16b, vt2.16b}, [xn]
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_LD1Twov16b_POST: {  // ld1 {vt1.16b, vt2.16b}, [xn],
                                             //   #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_LD1D: {  // ld1d {zt.d}, pg/z, [xn, xm, lsl #3]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 64;

      const uint64_t base = operands[1].get<uint64_t>();
      const uint64_t offset = operands[2].get<uint64_t>();

      std::vector<MemoryAccessTarget> addresses;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[(int)i / 8] & shifted_active) {
          addresses.push_back({base + ((offset + i) * 8), 8, 0, 1});
        }
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_LD1D_IMM_REAL: {  // ld1d {zt.d}, pg/z, [xn{, #imm, mul
                                           // vl}]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 64;

      const uint64_t base = operands[1].get<uint64_t>();
      const uint64_t offset =
          static_cast<uint64_t>(metadata.operands[2].mem.disp);

      std::vector<MemoryAccessTarget> addresses;

      uint64_t addr = base + (offset * partition_num * 8);

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[(int)i / 8] & shifted_active) {
          addresses.push_back({addr, 8, 0, 1});
        }
        addr += 8;
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_LD1W: {  // ld1w {zt.s}, pg/z, [xn, xm, lsl #2]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 32;

      const uint64_t base = operands[1].get<uint64_t>();
      const uint64_t offset = operands[2].get<uint64_t>();

      std::vector<MemoryAccessTarget> addresses;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[(int)i / 16] & shifted_active) {
          addresses.push_back({base + ((offset + i) * 4), 4, 0, 1});
        }
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_LD1W_IMM_REAL: {  // ld1w {zt.s}, pg/z, [xn{, #imm, mul
                                           // vl}]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 32;

      const uint64_t base = operands[1].get<uint64_t>();
      const uint64_t offset =
          static_cast<uint64_t>(metadata.operands[2].mem.disp);

      std::vector<MemoryAccessTarget> addresses;

      uint64_t addr = base + (offset * partition_num * 4);

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[(int)i / 16] & shifted_active) {
          addresses.push_back({addr, 4, 0, 1});
        }
        addr += 4;
      }

      setMemoryAddresses(addresses);
      break;
    }
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
    case Opcode::AArch64_LDRDpost: {  // ldr dt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 8, 1}});
      break;
    }
    case Opcode::AArch64_LDRDpre: {  // ldr dt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
      break;
    }
    case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm{, extend {amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8, 1}});
      break;
    }
    case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8, 1}});
      break;
    }
    case Opcode::AArch64_LDRDui: {  // ldr dt, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
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
    case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm{, extend {#amount}}]
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
    case Opcode::AArch64_LDRQpost: {  // ldr qt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 16, 1}});
      break;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 16, 1}});
      break;
    }
    case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 16,
            1}});
      break;
    }
    case Opcode::AArch64_LDRSpost: {  // ldr st, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4, 1}});
      break;
    }
    case Opcode::AArch64_LDRSpre: {  // ldr st, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4,
            1}});
      break;
    }
    case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4, 1}});
      break;
    }
    case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4, 1}});
      break;
    }
    case Opcode::AArch64_LDRSui: {  // ldr st, [xn, #imm] {
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4,
            1}});
      break;
    }
    case Opcode::AArch64_LDRSWl: {  // ldrsw xt, #imm
      setMemoryAddresses({{metadata.operands[1].imm + instructionAddress_, 4}});
      break;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_LDRWpre: {  // ldr wt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_LDRWroW: {  // ldr wt, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
      break;
    }
    case Opcode::AArch64_LDRWroX: {  // ldr wt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
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
    case Opcode::AArch64_LDRXroW: {  // ldr xt, [xn, wn{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8}});
      break;
    }
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend {#amount}}]
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
    case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4, 1}, {base + 4, 4, 1}});
      break;
    }
    case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_LDPDpost: {  // ldp dt1, dt2, [xn], #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_LDPDpre: {  // ldp dt1, dt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_LDPQpost: {  // ldp qt1, qt2, [xn], #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_LDPQpre: {  // ldp qt1, qt2, [xn, #imm]!
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_LDPSi: {  // ldp st1, st2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4, 1}, {base + 4, 4, 1}});
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
    case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 1}});
      break;
    }
    case Opcode::AArch64_LDRSBWui: {  // ldrsb xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRSHWui: {  // ldrsh wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
      break;
    }
    case Opcode::AArch64_LDRSHXui: {  // ldrsh xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
      break;
    }
    case Opcode::AArch64_LDRSWpost: {  // ldrsw xt, [xn], #simm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
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
    case Opcode::AArch64_LDURDi: {  // ldur dt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
      break;
    }
    case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 16,
            1}});
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
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend {#amount}}]
      // TODO: Implement prefetching
      break;
    }
    case Opcode::AArch64_ST1D: {  // st1d {zt.d}, pg, [xn, xm, lsl #3]
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 64;

      const uint64_t base = operands[2].get<uint64_t>();
      const uint64_t offset = operands[3].get<uint64_t>();

      std::vector<MemoryAccessTarget> addresses;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[(int)i / 8] & shifted_active) {
          addresses.push_back({base + ((offset + i) * 8), 8, 0, 1});
        }
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_ST1D_IMM: {  // st1d {zt.d}, pg, [xn{, #imm, mul vl}]
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 64;

      const uint64_t base = operands[2].get<uint64_t>();
      const uint64_t offset =
          static_cast<uint64_t>(metadata.operands[2].mem.disp);

      std::vector<MemoryAccessTarget> addresses;

      uint64_t addr = base + (offset * partition_num * 8);

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[(int)i / 8] & shifted_active) {
          addresses.push_back({addr, 8, 0, 1});
        }
        addr += 8;
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_ST1W: {  // st1w {zt.s}, pg, [xn, xm, lsl #2]
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 32;

      const uint64_t base = operands[2].get<uint64_t>();
      const uint64_t offset = operands[3].get<uint64_t>();

      std::vector<MemoryAccessTarget> addresses;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[(int)i / 16] & shifted_active) {
          addresses.push_back({base + ((offset + i) * 4), 4, 0, 1});
        }
      }

      setMemoryAddresses(addresses);
      break;
    }
    case Opcode::AArch64_ST1W_IMM: {  // st1w {zt.s}, pg, [xn{, #imm, mul vl}]
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint8_t partition_num = VL_bits / 32;

      const uint64_t base = operands[2].get<uint64_t>();
      const uint64_t offset =
          static_cast<uint64_t>(metadata.operands[2].mem.disp);

      std::vector<MemoryAccessTarget> addresses;

      uint64_t addr = base + (offset * partition_num * 4);

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[(int)i / 16] & shifted_active) {
          addresses.push_back({addr, 4, 0, 1});
        }
        addr += 4;
      }
      setMemoryAddresses(addresses);
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
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_STPDpost: {  // stp dt1, dt2, [xn], #imm
      uint64_t base = operands[2].get<uint64_t>();
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_STPDpre: {  // stp dt1, dt2, [xn, #imm]!
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8, 1}, {base + 8, 8, 1}});
      break;
    }
    case Opcode::AArch64_STPSi: {  // stp st1, st2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4, 1}, {base + 4, 4, 1}});
      break;
    }
    case Opcode::AArch64_STPSpost: {  // stp st1, st2, [xn], #imm
      uint64_t base = operands[2].get<uint64_t>();
      setMemoryAddresses({{base, 4, 1}, {base + 4, 4, 1}});
      break;
    }
    case Opcode::AArch64_STPSpre: {  // stp st1, st2, [xn, #imm]!
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 4, 1}, {base + 4, 4, 1}});
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
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
      break;
    }
    case Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      uint64_t base = operands[2].get<uint64_t>();
      setMemoryAddresses({{base, 16, 1}, {base + 16, 16, 1}});
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
    case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 8, 1}});
      break;
    }
    case Opcode::AArch64_STRDpre: {  // str dd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
      break;
    }
    case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8, 1}});
      break;
    }
    case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8, 1}});
      break;
    }
    case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
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
      setMemoryAddresses({{operands[1].get<uint64_t>(), 16, 1}});
      break;
    }
    case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 16, 1}});
      break;
    }
    case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 16,
            1}});
      break;
    }
    case Opcode::AArch64_STRSpost: {  // str st, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4, 1}});
      break;
    }
    case Opcode::AArch64_STRSpre: {  // str sd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4,
            1}});
      break;
    }
    case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4, 1}});
      break;
    }
    case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4, 1}});
      break;
    }
    case Opcode::AArch64_STRSui: {  // str st, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4,
            1}});
      break;
    }
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
      break;
    }
    case Opcode::AArch64_STRWpre: {  // str wd, [xn, #imm]!
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case Opcode::AArch64_STRWroW: {  // str wd, [xn, wm{, extend {#amount}}]
      uint64_t offset =
          extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
      break;
    }
    case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend {#amount}}]
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
    case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend {#amount}}]
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
    case Opcode::AArch64_STURDi: {  // stur dt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8,
            1}});
      break;
    }
    case Opcode::AArch64_STURQi: {  // stur qt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 16,
            1}});
      break;
    }
    case Opcode::AArch64_STURSi: {  // stur st, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4,
            1}});
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
      exceptionEncountered_ = true;
      exception_ = InstructionException::ExecutionNotYetImplemented;
      break;
  }
  return getGeneratedAddresses();
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng