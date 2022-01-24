#include <cmath>
#include <iostream>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void generateContiguousAddresses(
    uint64_t base, uint16_t num, uint8_t size,
    std::vector<simeng::MemoryAccessTarget>& addresses) {
  for (uint16_t addr = 0; addr < num; addr++) {
    addresses.push_back({base + (addr * size), size});
  }
}

span<const MemoryAccessTarget> Instruction::generateAddresses() {
  assert((isLoad() || isStoreAddress()) &&
         "generateAddresses called on non-load-or-store instruction");
  if (microOpcode_ == MicroOpcode::LDR_ADDR) {
    std::vector<simeng::MemoryAccessTarget> addresses;
    generateContiguousAddresses(
        operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1,
        dataSize_, addresses);
    std::cout << "### LDR_ADDR: " << getSequenceId() << ":"
              << getInstructionId() << ":0x" << std::hex
              << getInstructionAddress() << std::dec << ":" << getMicroOpIndex()
              << " -> 0x" << std::hex << operands[0].get<uint64_t>() << std::dec
              << " + " << metadata.operands[1].mem.disp << " = 0x" << std::hex
              << (operands[0].get<uint64_t>() + metadata.operands[1].mem.disp)
              << std::dec << std::endl;

    setMemoryAddresses(addresses);
  } else if (microOpcode_ == MicroOpcode::STR_ADDR) {
    std::vector<simeng::MemoryAccessTarget> addresses;
    generateContiguousAddresses(
        operands[0].get<uint64_t>() + metadata.operands[0].mem.disp, 1,
        dataSize_, addresses);
    std::cout << "### STR_ADDR: " << getSequenceId() << ":"
              << getInstructionId() << ":0x" << std::hex
              << getInstructionAddress() << std::dec << ":" << getMicroOpIndex()
              << " -> 0x" << std::hex << operands[0].get<uint64_t>() << std::dec
              << " + " << metadata.operands[0].mem.disp << " = 0x" << std::hex
              << (operands[0].get<uint64_t>() + metadata.operands[0].mem.disp)
              << std::dec << std::endl;

    setMemoryAddresses(addresses);
  } else {
    const uint16_t VL_bits = architecture_.getVectorLength();
    switch (metadata.opcode) {
      case Opcode::AArch64_CASALW: {  // casal ws, wt, [xn|sp]
        setMemoryAddresses({{operands[2].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_CASALX: {  // casal xs, xt, [xn|sp]
        setMemoryAddresses({{operands[2].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1i32: {  // ld1 {vt.s}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LD1i64: {  // ld1 {vt.d}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1i64_POST: {  // ld1 {vt.d}[index], [xn], #8
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1RD_IMM: {  // ld1rd {zt.d}, pg/z, [xn, #imm]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        for (int i = 0; i < 4; i++) {
          if (p[i] != 0) {
            setMemoryAddresses(
                {{operands[1].get<uint64_t>() + metadata.operands[2].mem.disp,
                  8}});
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
                {{operands[1].get<uint64_t>() + metadata.operands[2].mem.disp,
                  4}});
            break;
          }
        }
        break;
      }
      case Opcode::AArch64_LD1Rv16b: {  // ld1r {vt.16b}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv16b_POST: {  // ld1r {vt.16b}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv1d: {  // ld1r {vt.1d}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv1d_POST: {  // ld1r {vt.1d}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv2d: {  // ld1r {vt.2d}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2d_POST: {  // ld1r {vt.2d}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2s: {  // ld1r {vt.2s}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2s_POST: {  // ld1r {vt.2s}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv4h: {  // ld1r {vt.4h}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv4h_POST: {  // ld1r {vt.4h}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8b: {  // ld1r {vt.8b}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8b_POST: {  // ld1r {vt.8b}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8h: {  // ld1r {vt.8h}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv8h_POST: {  // ld1r {vt.8h}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv4s: {  // ld1r {vt.4s}, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv4s_POST: {  // ld1r {vt.4s}, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Twov16b: {  // ld1 {vt1.16b, vt2.16b}, [xn]
        uint64_t base = operands[0].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LD1Twov16b_POST: {  // ld1 {vt1.16b, vt2.16b}, [xn],
                                               //   #imm
        uint64_t base = operands[0].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LD1B: {  // ld1b {zt.b}, pg/z, [xn, xm]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset = operands[2].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << (i % 64);
          if (p[i / 64] & shifted_active) {
            addresses.push_back({base + (offset + i), 1});
          }
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD1D: {  // ld1d {zt.d}, pg/z, [xn, xm, lsl #3]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset = operands[2].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 8), 8});
          }
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD1D_IMM_REAL: {  // ld1d {zt.d}, pg/z, [xn{, #imm,
                                             // mul vl}]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        uint64_t addr = base + (offset * partition_num * 8);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            addresses.push_back({addr, 8});
          }
          addr += 8;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD1H: {  // ld1h {zt.h}, pg/z, [xn, xm, lsl #1]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 16;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset = operands[2].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 32) * 2);
          if (p[i / 32] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 2), 2});
          }
        }

        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_LD1W: {  // ld1w {zt.s}, pg/z, [xn, xm, lsl #2]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset = operands[2].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 4), 4});
          }
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD1W_IMM_REAL: {  // ld1w {zt.s}, pg/z, [xn{, #imm,
                                             // mul vl}]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        uint64_t addr = base + (offset * partition_num * 4);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            addresses.push_back({addr, 4});
          }
          addr += 4;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD2Twov4s_POST: {  // ld2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
        const uint64_t base = operands[2].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LDADDLW:  // ldaddl ws, wt, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LDADDW: {  // ldadd ws, wt, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDARB: {  // ldarb wt, [xn]
        setMemoryAddresses({{operands[0].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_LDARW: {  // ldar wt, [xn]
        setMemoryAddresses({{operands[0].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDARX: {  // ldar xt, [xn]
        setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
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
        setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LDRDpre: {  // ldr dt, [xn, #imm]!
        setMemoryAddresses(
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
        break;
      }
      case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm{, extend {amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 8}});
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
        setMemoryAddresses({{operands[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 16}});
        break;
      }
      case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm] {
        setMemoryAddresses(
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp,
              16}});
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
      case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm{, extend {#amount}}]
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
      case Opcode::AArch64_LDRSWl: {  // ldrsw xt, #imm
        setMemoryAddresses(
            {{metadata.operands[1].imm + instructionAddress_, 4}});
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
        setMemoryAddresses(
            {{metadata.operands[1].imm + instructionAddress_, 8}});
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
      case Opcode::AArch64_LDR_PXI: {  // ldr pt, [xn{, #imm, mul vl}]
        const uint64_t PL_bits = VL_bits / 8;
        const uint16_t partition_num = PL_bits / 8;

        const uint64_t base = operands[0].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[1].mem.disp);

        std::vector<MemoryAccessTarget> addresses(partition_num);

        uint64_t addr = base + (offset * partition_num);

        for (int i = 0; i < partition_num; i++) {
          addresses[i] = {addr, 1};
          addr += 1;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LDR_ZXI: {  // ldr zt, [xn{, #imm, mul vl}]
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = operands[0].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[1].mem.disp);

        std::vector<MemoryAccessTarget> addresses(partition_num);

        uint64_t addr = base + (offset * partition_num);
        for (int i = 0; i < partition_num; i++) {
          addresses[i] = {addr, 1};
          addr += 1;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_LDPDpost: {  // ldp dt1, dt2, [xn], #imm
        uint64_t base = operands[0].get<uint64_t>();
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_LDPDpre: {  // ldp dt1, dt2, [xn, #imm]
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LDPQpost: {  // ldp qt1, qt2, [xn], #imm
        uint64_t base = operands[0].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LDPQpre: {  // ldp qt1, qt2, [xn, #imm]!
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LDPSWi: {  // ldpsw xt1, xt2, [xn {, #imm}]
        uint64_t base =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
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
      case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend
                                         // {#amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend
                                         // {#amount}}]
        uint64_t offset =
            extendOffset(operands[1].get<uint32_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend
                                        // {#amount}}]
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
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
        break;
      }
      case Opcode::AArch64_LDURHHi: {  // ldurh wt, [xn, #imm]
        setMemoryAddresses(
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
        break;
      }
      case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
        setMemoryAddresses(
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_LDURSWi: {  // ldursw xt, [xn, #imm]
        setMemoryAddresses(
            {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
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
      case Opcode::AArch64_LDXRX: {  // ldxr xt, [xn]
        setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend {#amount}}]
        // TODO: Implement prefetching
        break;
      }
      case Opcode::AArch64_ST1B: {  // st1b {zt.b}, pg, [xn, xm]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset = operands[3].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << (i % 64);
          if (p[i / 64] & shifted_active) {
            addresses.push_back({base + (offset + i), 1});
          }
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_SST1B_D: {  // st1b {zd.d}, pg, [xn, zm.d]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t* offset = operands[3].getAsVector<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = base + offset[i];
            addresses.push_back({addr, 1});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_SST1D: {  // st1d {zt.d}, pg, [xn, zm.d]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t* offset = operands[3].getAsVector<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = base + offset[i];
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_SST1D_SCALED: {  // st1d {zt.d}, pg, [xn, zm.d, lsl
                                            // #3]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t* offset = operands[3].getAsVector<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = base + (offset[i] << 3);
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_ST1D: {  // st1d {zt.d}, pg, [xn, xm, lsl #3]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset = operands[3].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 8), 8});
          }
        }

        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_ST1D_IMM: {  // st1d {zt.d}, pg, [xn{, #imm, mul vl}]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        uint64_t addr = base + (offset * partition_num * 8);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            addresses.push_back({addr, 8});
          }
          addr += 8;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1W: {  // st1w {zt.s}, pg, [xn, xm, lsl #2]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset = operands[3].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 4), 4});
          }
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1W_D: {  // st1w {zt.d}, pg, [xn, xm, lsl #2]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset = operands[3].get<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            addresses.push_back({base + ((offset + i) * 4), 4});
          }
        }

        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_ST1W_IMM: {  // st1w {zt.s}, pg, [xn{, #imm, mul vl}]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = operands[2].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        uint64_t addr = base + (offset * partition_num * 4);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            addresses.push_back({addr, 4});
          }
          addr += 4;
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_SST1W_D_IMM: {  // st1w {zt.d}, pg, [zn.d{, #imm}]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = operands[2].getAsVector<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = n[i] + (offset * 4);
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_SST1W_IMM: {  // st1w {zt.s}, pg, [zn.s{, #imm}]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint32_t* n = operands[2].getAsVector<uint32_t>();
        const uint64_t offset = static_cast<uint64_t>(
            static_cast<uint32_t>(metadata.operands[2].mem.disp));

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            uint64_t addr = static_cast<uint64_t>(n[i]) + (offset * 4);
            addresses.push_back({addr, 4});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_GLD1D_REAL: {  // ld1d {zt.d}, pg/z, [xn, zm.d]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t* offset = operands[2].getAsVector<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = base + offset[i];
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_GLD1D_SCALED_REAL: {  // ld1d {zt.d}, pg/z, [xn,
                                                 // zm.d, LSL #3]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t* offset = operands[2].getAsVector<uint64_t>();

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = base + (offset[i] << 3);
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_GLD1D_IMM_REAL: {  // ld1d {zd.d}, pg/z, [zn.d{,
                                              // #imm}]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = operands[1].getAsVector<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = n[i] + (offset * 8);
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_GLD1SW_D_IMM_REAL: {  // ld1sw {zd.d}, pg/z, [zn.d{,
                                                 // #imm}]
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = operands[1].getAsVector<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = n[i] + (offset * 4);
            addresses.push_back({addr, 4});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_SST1D_IMM: {  // st1d {zt.d}, pg, [zn.d{, #imm}]
        const uint64_t* p = operands[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = operands[2].getAsVector<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[2].mem.disp);

        std::vector<MemoryAccessTarget> addresses;

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = n[i] + (offset * 8);
            addresses.push_back({addr, 8});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_ST1Twov16b: {  // st1v {vt.16b, vt2.16b}, [xn]
        const uint64_t base = operands[2].get<uint64_t>();
        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(32);

        for (int i = 0; i < 32; i++) {
          addresses.push_back({base + i, 1});
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1i8_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i8: {  // st1 {vt.b}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_ST1i16_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i16: {  // st1 {vt.h}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 2}});
        break;
      }
      case Opcode::AArch64_ST1i32_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i32: {  // st1 {vt.s}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_ST1i64_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i64: {  // st1 {vt.d}[index], [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_ST2Twov4s_POST: {  // st2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
        const uint64_t base = operands[2].get<uint64_t>();
        std::vector<MemoryAccessTarget> addresses;
        addresses.reserve(8);
        for (int i = 0; i < 8; i++) {
          addresses.push_back({base + 4 * i, 4});
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_STLRB: {  // stlrb wt, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_STLRW: {  // stlr wt, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_STLRX: {  // stlr xt, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
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
      case Opcode::AArch64_STPDpost: {  // stp dt1, dt2, [xn], #imm
        uint64_t base = operands[2].get<uint64_t>();
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_STPDpre: {  // stp dt1, dt2, [xn, #imm]!
        uint64_t base =
            operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_STPSi: {  // stp st1, st2, [xn, #imm]
        uint64_t base =
            operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_STPSpost: {  // stp st1, st2, [xn], #imm
        uint64_t base = operands[2].get<uint64_t>();
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_STPSpre: {  // stp st1, st2, [xn, #imm]!
        uint64_t base =
            operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
        uint64_t base =
            operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
        setMemoryAddresses({{base, 8}, {base + 8, 8}});
        break;
      }
      case Opcode::AArch64_STPXpost: {  // stp xt1, xt2, [xn], #imm
        uint64_t base = operands[2].get<uint64_t>();
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
      case Opcode::AArch64_STPQpre: {  // stp qt1, qt2, [xn, #imm]!
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
      case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_STRDpre: {  // str dd, [xn, #imm]!
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
        break;
      }
      case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
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
      case Opcode::AArch64_STRQpre: {  // str qt, [xn, #imm]!
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 16}});
        break;
      }
      case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_STRSpost: {  // str st, [xn], #imm
        setMemoryAddresses({{operands[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_STRSpre: {  // str sd, [xn, #imm]!
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
        break;
      }
      case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[2].get<uint32_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, extend {#amount}}]
        uint64_t offset =
            extendOffset(operands[2].get<uint64_t>(), metadata.operands[1]);
        setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRSui: {  // str st, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
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
      case Opcode::AArch64_STR_PXI: {  // str pt, [xn{, #imm, mul vl}]
        const uint64_t PL_bits = VL_bits / 8;
        const uint16_t partition_num = PL_bits / 8;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[1].mem.disp);

        std::vector<MemoryAccessTarget> addresses(partition_num);

        uint64_t addr = base + (offset * partition_num);

        for (int i = 0; i < partition_num; i++) {
          addresses[i] = {addr, 1};
          addr += 1;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_STR_ZXI: {  // str zt, [xn{, #imm, mul vl}]
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = operands[1].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata.operands[1].mem.disp);

        std::vector<MemoryAccessTarget> addresses(partition_num);

        uint64_t addr = base + (offset * partition_num);
        for (int i = 0; i < partition_num; i++) {
          addresses[i] = {addr, 1};
          addr += 1;
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
        break;
      }
      case Opcode::AArch64_STURDi: {  // stur dt, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
        break;
      }
      case Opcode::AArch64_STURHHi: {  // sturh wt, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 2}});
        break;
      }
      case Opcode::AArch64_STURQi: {  // stur qt, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_STURSi: {  // stur st, [xn, #imm]
        setMemoryAddresses(
            {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
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
      case Opcode::AArch64_STXRX: {  // stxr ws, xt, [xn]
        setMemoryAddresses({{operands[1].get<uint64_t>(), 8}});
        break;
      }
      default:
        exceptionEncountered_ = true;
        exception_ = InstructionException::ExecutionNotYetImplemented;
        break;
    }
  }
  return getGeneratedAddresses();
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng