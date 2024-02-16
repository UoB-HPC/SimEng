#include <cmath>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/arch/aarch64/helpers/auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void generateContiguousAddresses(
    uint64_t baseAddr, uint16_t numVecElems, uint8_t size,
    std::vector<simeng::memory::MemoryAccessTarget>& addresses) {
  for (uint16_t i = 0; i < numVecElems; i++) {
    addresses.push_back({baseAddr + (i * size), size});
  }
}

void generatePredicatedContiguousAddressBlocks(
    uint64_t baseAddr, uint16_t numVecElems, uint8_t elemSize, uint8_t predSize,
    const uint64_t* pred,
    std::vector<simeng::memory::MemoryAccessTarget>& addresses) {
  bool recordingBlock = false;
  uint64_t currAddr = 0;
  uint16_t currSize = 0;
  uint64_t numPreds = (64 / predSize);  // Number of predicates per uint64_t
  for (uint64_t i = 0; i < numVecElems; i++) {
    uint64_t shifted_active = 1ull << ((i % numPreds) * predSize);
    if (pred[i / numPreds] & shifted_active) {
      // If the lane is active and no address block is being recorded,
      // start
      if (!recordingBlock) {
        currAddr = baseAddr + (i * elemSize);
        currSize = 0;
        recordingBlock = true;
      }
      currSize += elemSize;
    } else if (recordingBlock) {
      // Record the currently recorded address block
      addresses.push_back({currAddr, currSize});
      recordingBlock = false;
    }
  }

  // Record any remaining address blocks
  if (recordingBlock) addresses.push_back({currAddr, currSize});
}

span<const memory::MemoryAccessTarget> Instruction::generateAddresses() {
  assert((isLoad() || isStoreAddress()) &&
         "generateAddresses called on non-load-or-store instruction");
  if (isMicroOp_) {
    switch (microOpcode_) {
      case MicroOpcode::LDR_ADDR: {
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
            1, dataSize_, addresses);

        setMemoryAddresses(addresses);
        break;
      }
      case MicroOpcode::STR_ADDR: {
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[0].get<uint64_t>() + metadata_.operands[0].mem.disp,
            1, dataSize_, addresses);

        setMemoryAddresses(addresses);
        break;
      }
      default:
        exceptionEncountered_ = true;
        exception_ = InstructionException::ExecutionNotYetImplemented;
        break;
    }
  } else {
    // 0th bit of SVCR register determines if streaming-mode is enabled.
    const bool SMenabled = architecture_.getSVCRval() & 1;
    // When streaming mode is enabled, the architectural vector length goes from
    // SVE's VL to SME's SVL.
    const uint16_t VL_bits = SMenabled
                                 ? architecture_.getStreamingVectorLength()
                                 : architecture_.getVectorLength();
    switch (metadata_.opcode) {
      case Opcode::AArch64_CASALW: {  // casal ws, wt, [xn|sp]
        setMemoryAddresses({{sourceValues_[2].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_CASALX: {  // casal xs, xt, [xn|sp]
        setMemoryAddresses({{sourceValues_[2].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_CASAW: {  // casa ws, wt, [xn|sp]
        setMemoryAddresses({{sourceValues_[2].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_CASAX: {  // casa xs, xt, [xn|sp]
        setMemoryAddresses({{sourceValues_[2].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1_MXIPXX_V_D:    // ld1d {zatv.d[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, lsl #3}]
      case Opcode::AArch64_LD1_MXIPXX_H_D: {  // ld1d {zath.d[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, lsl #3}]
        // SME
        const uint16_t partition_num = VL_bits / 64;
        const uint64_t n = sourceValues_[partition_num + 2].get<uint64_t>();
        uint64_t m = 0;
        if (metadata_.operands[2].mem.index)
          m = sourceValues_[partition_num + 3].get<uint64_t>() << 3;
        setMemoryAddresses({(n + m), static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1_MXIPXX_V_S:    // ld1w {zatv.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
      case Opcode::AArch64_LD1_MXIPXX_H_S: {  // ld1w {zath.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME
        const uint16_t partition_num = VL_bits / 32;
        const uint64_t n = sourceValues_[partition_num + 2].get<uint64_t>();
        uint64_t m = 0;
        if (metadata_.operands[2].mem.index)
          m = sourceValues_[partition_num + 3].get<uint64_t>() << 2;
        setMemoryAddresses({(n + m), static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1i32: {  // ld1 {vt.s}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LD1i64: {  // ld1 {vt.d}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1i64_POST: {  // ld1 {vt.d}[index], [xn], #8
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1RD_IMM: {  // ld1rd {zt.d}, pg/z, [xn, #imm]
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        for (int i = 0; i < 4; i++) {
          if (p[i] != 0) {
            setMemoryAddresses({{sourceValues_[1].get<uint64_t>() +
                                     metadata_.operands[2].mem.disp,
                                 8}});
            break;
          }
        }
        break;
      }
      case Opcode::AArch64_LD1RQ_D_IMM: {  // ld1rqd {zd.d}, pg/z, [xn{, #imm}]
        uint64_t addr =
            sourceValues_[1].get<uint64_t>() + metadata_.operands[2].mem.disp;
        setMemoryAddresses({addr, static_cast<uint16_t>(16)});
        break;
      }
      case Opcode::AArch64_LD1RQ_W: {  // ld1rqw {zd.s}, pg/z, [xn, xm, lsl #2]
        uint64_t addr = sourceValues_[1].get<uint64_t>() +
                        (sourceValues_[2].get<uint64_t>() * 4);
        setMemoryAddresses({addr, static_cast<uint16_t>(16)});
        break;
      }
      case Opcode::AArch64_LD1RQ_W_IMM: {  // ld1rqw {zd.s}, pg/z, [xn{, #imm}]
        uint64_t addr =
            sourceValues_[1].get<uint64_t>() + metadata_.operands[2].mem.disp;
        setMemoryAddresses({addr, static_cast<uint16_t>(16)});
        break;
      }
      case Opcode::AArch64_LD1RW_IMM: {  // ld1rw {zt.s}, pg/z, [xn, #imm]
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        for (int i = 0; i < 4; i++) {
          if (p[i] != 0) {
            setMemoryAddresses({{sourceValues_[1].get<uint64_t>() +
                                     metadata_.operands[2].mem.disp,
                                 4}});
            break;
          }
        }
        break;
      }
      case Opcode::AArch64_LD1Rv16b: {  // ld1r {vt.16b}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv16b_POST: {  // ld1r {vt.16b}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv1d: {  // ld1r {vt.1d}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv1d_POST: {  // ld1r {vt.1d}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv2d: {  // ld1r {vt.2d}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2d_POST: {  // ld1r {vt.2d}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2s: {  // ld1r {vt.2s}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv2s_POST: {  // ld1r {vt.2s}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv4h: {  // ld1r {vt.4h}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv4h_POST: {  // ld1r {vt.4h}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8b: {  // ld1r {vt.8b}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8b_POST: {  // ld1r {vt.8b}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LD1Rv8h: {  // ld1r {vt.8h}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv8h_POST: {  // ld1r {vt.8h}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv4s: {  // ld1r {vt.4s}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Rv4s_POST: {  // ld1r {vt.4s}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Onev16b: {  // ld1 {vt.16b}, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Onev16b_POST: {  // ld1 {vt.16b}, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 16}});
        break;
      }
      case Opcode::AArch64_LD1Fourv16b:  // ld1 {vt1.16b, vt2.16b, vt3.16b,
                                         // vt4.16b}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Fourv16b_POST:  // ld1 {vt1.16b, vt2.16b, vt3.16b,
                                              // vt4.16b}, [xn], <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_LD1Fourv2d:  // ld1 {vt1.2d, vt2.2d, vt3.2d, vt4.2d},
                                        // [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Fourv2d_POST:  // ld1 {vt1.2d, vt2.2d, vt3.2d,
                                             // vt4.2d}, [xn], <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_LD1Fourv4s:  // ld1 {vt1.4s, vt2.4s, vt3.4s, vt4.4s},
                                        // [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Fourv4s_POST: {  // ld1 {vt1.4s, vt2.4s, vt3.4s,
                                               // vt4.4s}, [xn], <#imm|xm>
        uint64_t base = sourceValues_[0].get<uint64_t>();
        setMemoryAddresses(
            {{base, 16}, {base + 16, 16}, {base + 32, 16}, {base + 48, 16}});
        break;
      }
      case Opcode::AArch64_LD1Twov16b:  // ld1 {vt1.16b, vt2.16b}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Twov16b_POST:  // ld1 {vt1.16b, vt2.16b}, [xn],
                                             // <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_LD1Twov2d:  // ld1 {vt1.2d, vt2.2d}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Twov2d_POST:  // ld1 {vt1.2d, vt2.2d}, [xn],
                                            // <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_LD1Twov4s:  // ld1 {vt1.4s, vt2.4s}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LD1Twov4s_POST: {  // ld1 {vt1.4s, vt2.4s}, [xn],
                                              // <#imm|xm>
        uint64_t base = sourceValues_[0].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LD1B: {  // ld1b {zt.b}, pg/z, [xn, xm]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t offset = sourceValues_[2].get<uint64_t>();

        setMemoryAddresses({base + offset, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1B_IMM_REAL: {  // ld1b {zt.b}, pg/z, [xn{, #imm,
                                             // mul vl}]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);
        uint64_t addr = base + (offset * (VL_bits / 8));

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1D: {  // ld1d {zt.d}, pg/z, [xn, xm, lsl #3]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t offset = sourceValues_[2].get<uint64_t>();
        const uint64_t addr = base + (offset * 8);

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1D_IMM_REAL: {  // ld1d {zt.d}, pg/z, [xn{, #imm,
                                             // mul vl}]
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t offset =
            static_cast<uint64_t>(metadata_.operands[2].mem.disp);
        const uint64_t addr = base + (offset * partition_num * 8);

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1H: {  // ld1h {zt.h}, pg/z, [xn, xm, lsl #1]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t offset = sourceValues_[2].get<uint64_t>();
        const uint64_t addr = base + (offset * 2);

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1W: {  // ld1w {zt.s}, pg/z, [xn, xm, lsl #2]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t offset = sourceValues_[2].get<uint64_t>();
        const uint64_t addr = base + (offset * 4);

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD1W_IMM_REAL: {  // ld1w {zt.s}, pg/z, [xn{, #imm,
                                             // mul vl}]
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<uint64_t>(metadata_.operands[2].mem.disp);
        const uint64_t addr = base + (offset * partition_num * 4);

        setMemoryAddresses({addr, static_cast<uint16_t>(VL_bits / 8)});
        break;
      }
      case Opcode::AArch64_LD2D: {  // ld2d {zt1.d, zt2.d}, pg/z, [xn|sp, xm,
                                    // lsl #3]
        const uint64_t base = sourceValues_[1].get<uint64_t>();
        uint64_t offset = sourceValues_[2].get<uint64_t>();
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(2);

        uint64_t addr = base + (offset * 8);

        uint16_t blockSize = VL_bits / 8;
        addresses.push_back({addr, blockSize});
        addresses.push_back({addr + blockSize, blockSize});

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD2D_IMM: {  // ld2d {zt1.d, zt2.d}, pg/z,
                                        // [xn|sp{, #imm, MUL VL}]
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[3].mem.disp);
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(2);

        uint64_t addr = base + (offset * partition_num * 8);

        uint16_t blockSize = VL_bits / 8;
        addresses.push_back({addr, blockSize});
        addresses.push_back({addr + blockSize, blockSize});

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD3D_IMM: {  // ld3d {zt1.d, zt2.d, zt3.d}, pg/z,
                                        // [xn|sp{, #imm, MUL VL}]
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[4].mem.disp);
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(3);

        uint64_t addr = base + (offset * partition_num * 8);

        uint16_t blockSize = VL_bits / 8;
        addresses.push_back({addr, blockSize});
        addresses.push_back({addr + blockSize, blockSize});
        addresses.push_back({addr + 2 * blockSize, blockSize});

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD4D_IMM: {  // ld4d {zt1.d, zt2.d, zt3.d, zt4.d},
                                        // pg/z, [xn|sp{, #imm, MUL VL}]
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[5].mem.disp);
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(4);

        uint64_t addr = base + (offset * partition_num * 8);

        uint16_t blockSize = VL_bits / 8;
        addresses.push_back({addr, blockSize});
        addresses.push_back({addr + blockSize, blockSize});
        addresses.push_back({addr + 2 * blockSize, blockSize});
        addresses.push_back({addr + 3 * blockSize, blockSize});

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_LD2Twov4s: {  // ld2 {vt1.4s, vt2.4s}, [xn]
        [[fallthrough]];
      }
      case Opcode::AArch64_LD2Twov4s_POST: {  // ld2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
        const uint64_t base = sourceValues_[2].get<uint64_t>();
        setMemoryAddresses({{base, 16}, {base + 16, 16}});
        break;
      }
      case Opcode::AArch64_LDADDLW:  // ldaddl ws, wt, [xn]
        [[fallthrough]];
      case Opcode::AArch64_LDADDW: {  // ldadd ws, wt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDARB: {  // ldarb wt, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_LDARW: {  // ldar wt, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDARX: {  // ldar xt, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDAXRX: {  // ldaxr xd, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_LDRBBpost: {  // ldrb wt, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_LDRBBroW: {  // ldrb wt,
                                        //  [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 1}});
        break;
      }
      case Opcode::AArch64_LDRBBroX: {  // ldrb wt,
                                        //  [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 1}});
        break;
      }
      case Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm{, extend {amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_LDRBui:     // ldr bt, [xn, #imm]
      case Opcode::AArch64_LDRBpre:    // ldr bt, [xn, #imm]!
      case Opcode::AArch64_LDRDui:     // ldr dt, [xn, #imm]
      case Opcode::AArch64_LDRDpre:    // ldr dt, [xn, #imm]!
      case Opcode::AArch64_LDRHui:     // ldr ht, [xn, #imm]
      case Opcode::AArch64_LDRHpre:    // ldr ht, [xn, #imm]!
      case Opcode::AArch64_LDRQui:     // ldr qt, [xn, #imm]
      case Opcode::AArch64_LDRQpre:    // ldr qt, [xn, #imm]!
      case Opcode::AArch64_LDRSui:     // ldr st, [xn, #imm]
      case Opcode::AArch64_LDRSpre:    // ldr st, [xn, #imm]!
      case Opcode::AArch64_LDRWui:     // ldr wt, [xn, #imm]
      case Opcode::AArch64_LDRWpre:    // ldr wt, [xn, #imm]!
      case Opcode::AArch64_LDRXui:     // ldr xt, [xn, #imm]
      case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
            1, dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_LDRBpost:    // ldr bt, [xn], #imm
      case Opcode::AArch64_LDRDpost:    // ldr dt, [xn], #imm
      case Opcode::AArch64_LDRHpost:    // ldr ht, [xn], #imm
      case Opcode::AArch64_LDRQpost:    // ldr qt, [xn], #imm
      case Opcode::AArch64_LDRSpost:    // ldr st, [xn], #imm
      case Opcode::AArch64_LDRWpost:    // ldr wt, [xn], #imm
      case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
        std::vector<memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(sourceValues_[0].get<uint64_t>(), 1,
                                    dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 2}});
        break;
      }
      case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 16}});
        break;
      }
      case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRSWl: {  // ldrsw xt, #imm
        setMemoryAddresses(
            {{metadata_.operands[1].imm + instructionAddress_, 4}});
        break;
      }
      case Opcode::AArch64_LDRWroW: {  // ldr wt, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRWroX: {  // ldr wt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
        setMemoryAddresses(
            {{metadata_.operands[1].imm + instructionAddress_, 8}});
        break;
      }
      case Opcode::AArch64_LDRXroW: {  // ldr xt, [xn, wn{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_LDR_PXI: {  // ldr pt, [xn{, #imm, mul vl}]
        const uint64_t PL_bits = VL_bits / 8;
        const uint16_t partition_num = PL_bits / 8;

        const uint64_t base = sourceValues_[0].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[1].mem.disp);

        uint64_t addr = base + (offset * partition_num);

        setMemoryAddresses({addr, partition_num});
        break;
      }
      case Opcode::AArch64_LDR_ZXI: {  // ldr zt, [xn{, #imm, mul vl}]
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = sourceValues_[0].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[1].mem.disp);
        const uint64_t addr = base + (offset * partition_num);

        setMemoryAddresses({addr, partition_num});
        break;
      }
      case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
        uint64_t base =
            sourceValues_[0].get<uint64_t>() + metadata_.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_LDPDi:      // ldp dt1, dt2, [xn, #imm]
      case Opcode::AArch64_LDPDpre:    // ldp dt1, dt2, [xn, #imm!]
      case Opcode::AArch64_LDPQi:      // ldp qt1, qt2, [xn, #imm]
      case Opcode::AArch64_LDPQpre:    // ldp qt1, qt2, [xn, #imm!]
      case Opcode::AArch64_LDPSi:      // ldp st1, st2, [xn, #imm]
      case Opcode::AArch64_LDPSpre:    // ldp st1, st2, [xn, #imm!]
      case Opcode::AArch64_LDPWi:      // ldp wt1, wt2, [xn, #imm]
      case Opcode::AArch64_LDPWpre:    // ldp wt1, wt2, [xn, #imm!]
      case Opcode::AArch64_LDPXi:      // ldp xt1, xt2, [xn, #imm]
      case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm!]
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[0].get<uint64_t>() + metadata_.operands[2].mem.disp,
            2, dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_LDPDpost:    // ldp dt1, dt2, [xn], #imm
      case Opcode::AArch64_LDPQpost:    // ldp qt1, qt2, [xn], #imm
      case Opcode::AArch64_LDPSpost:    // ldp st1, st2, [xn], #imm
      case Opcode::AArch64_LDPWpost:    // ldp wt1, wt2, [xn], #imm
      case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
        std::vector<memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(sourceValues_[0].get<uint64_t>(), 2,
                                    dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_LDPSWi: {  // ldpsw xt1, xt2, [xn {, #imm}]
        uint64_t base =
            sourceValues_[0].get<uint64_t>() + metadata_.operands[2].mem.disp;
        setMemoryAddresses({{base, 4}, {base + 4, 4}});
        break;
      }
      case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend
                                         // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 1}});
        break;
      }
      case Opcode::AArch64_LDRSBWui: {  // ldrsb xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend
                                         // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend
                                         // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHWui: {  // ldrsh wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend
                                         // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend
                                         // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_LDRSHXui: {  // ldrsh xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_LDRSWpost: {  // ldrsw xt, [xn], #simm
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend
                                        // {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[1].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
        uint64_t base =
            sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp;
        setMemoryAddresses({{base, 4}});
        break;
      }
      case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_LDURDi: {  // ldur dt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              8}});
        break;
      }
      case Opcode::AArch64_LDURHHi: {  // ldurh wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_LDURSWi: {  // ldursw xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              4}});
        break;
      }
      case Opcode::AArch64_LDURSi: {  // ldur sd, [<xn|sp>{, #imm}]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              4}});
        break;
      }
      case Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              4}});
        break;
      }
      case Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[0].get<uint64_t>() + metadata_.operands[1].mem.disp,
              8}});
        break;
      }
      case Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_LDXRX: {  // ldxr xt, [xn]
        setMemoryAddresses({{sourceValues_[0].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend {#amount}}]
        // TODO: Implement prefetching
        break;
      }
      case Opcode::AArch64_ST1B: {  // st1b {zt.b}, pg, [xn, xm]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t offset = sourceValues_[3].get<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(base + offset, partition_num,
                                                  1, 1, p, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1B_IMM: {  // st1b {zt.b}, pg, [xn{, #imm, mul vl}]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);
        uint64_t addr = base + (offset * partition_num);

        generatePredicatedContiguousAddressBlocks(addr, partition_num, 1, 1, p,
                                                  addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_SST1B_D_REAL: {  // st1b {zd.d}, pg, [xn, zm.d]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t* offset = sourceValues_[3].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;

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
      case Opcode::AArch64_SST1D_REAL: {  // st1d {zt.d}, pg, [xn, zm.d]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t* offset = sourceValues_[3].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
      case Opcode::AArch64_SST1D_SCALED_SCALED_REAL: {  // st1d {zt.d}, pg, [xn,
                                                        // zm.d, lsl #3]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t* offset = sourceValues_[3].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t offset = sourceValues_[3].get<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(
            base + (offset * 8), partition_num, 8, 8, p, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1D_IMM: {  // st1d {zt.d}, pg, [xn{, #imm, mul vl}]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(
            base + (offset * partition_num * 8), partition_num, 8, 8, p,
            addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST2D_IMM: {  // st2d {zt1.d, zt2.d}, pg, [<xn|sp>{,
                                        // #imm, mul vl}]
        const uint64_t* p = sourceValues_[2].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[3].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[3].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num * 2);

        uint64_t addr = base + (offset * partition_num * 8);

        generatePredicatedContiguousAddressBlocks(addr, partition_num, 16, 8, p,
                                                  addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1_MXIPXX_H_D:    // st1d {zath.d[ws, #imm]}, pg,
                                              // [<xn|sp>{, xm, lsl #3}]
      case Opcode::AArch64_ST1_MXIPXX_V_D: {  // st1d {zatv.d[ws, #imm]}, pg,
                                              // [<xn|sp>{, xm, lsl #3}]
        // SME
        const uint16_t partition_num = VL_bits / 64;
        const uint64_t* pg =
            sourceValues_[partition_num + 1].getAsVector<uint64_t>();
        const uint64_t n = sourceValues_[partition_num + 2].get<uint64_t>();
        uint64_t m = 0;
        if (metadata_.operands[2].mem.index)
          m = sourceValues_[partition_num + 3].get<uint64_t>() << 3;

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks((n + m), partition_num, 8, 8,
                                                  pg, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1_MXIPXX_H_S:    // st1w {zath.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
      case Opcode::AArch64_ST1_MXIPXX_V_S: {  // st1w {zatv.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME
        const uint16_t partition_num = VL_bits / 32;
        const uint64_t* pg =
            sourceValues_[partition_num + 1].getAsVector<uint64_t>();
        const uint64_t n = sourceValues_[partition_num + 2].get<uint64_t>();
        uint64_t m = 0;
        if (metadata_.operands[2].mem.index)
          m = sourceValues_[partition_num + 3].get<uint64_t>() << 2;

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks((n + m), partition_num, 4, 4,
                                                  pg, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1W: {  // st1w {zt.s}, pg, [xn, xm, lsl #2]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t offset = sourceValues_[3].get<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(
            base + (offset * 4), partition_num, 4, 4, p, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1W_D: {  // st1w {zt.d}, pg, [xn, xm, lsl #2]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const uint64_t offset = sourceValues_[3].get<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(
            base + (offset * 4), partition_num, 4, 8, p, addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1W_IMM: {  // st1w {zt.s}, pg, [xn{, #imm, mul
                                        // vl}]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t base = sourceValues_[2].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        generatePredicatedContiguousAddressBlocks(
            base + (offset * partition_num * 4), partition_num, 4, 4, p,
            addresses);
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_SST1W_D_IMM: {  // st1w {zt.d}, pg, [zn.d{, #imm}]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = sourceValues_[2].getAsVector<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint32_t* n = sourceValues_[2].getAsVector<uint32_t>();
        const int64_t offset = static_cast<int64_t>(
            static_cast<int32_t>(metadata_.operands[2].mem.disp));

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t* offset = sourceValues_[2].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const uint64_t* offset = sourceValues_[2].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = sourceValues_[1].getAsVector<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
      case Opcode::AArch64_GLD1SW_D_IMM_REAL: {  // ld1sw {zd.d}, pg/z,
                                                 // [zn.d{, #imm}]
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = sourceValues_[1].getAsVector<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
      case Opcode::AArch64_GLD1W_D_SCALED_REAL: {  // ld1w {zd.d}, pg/z,
                                                   // [<xn|sp>, zm.d, lsl #2]
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t n = sourceValues_[1].get<uint64_t>();
        const uint64_t* m = sourceValues_[2].getAsVector<uint64_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            uint64_t addr = n + (m[i] * 4);
            addresses.push_back({addr, 4});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_GLD1W_SXTW_REAL: {  // ld1w {zd.s}, pg/z,
                                               // [<xn|sp>, zm.s, sxtw]
        const uint64_t* p = sourceValues_[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;

        const uint64_t n = sourceValues_[1].get<uint64_t>();
        const uint32_t* m = sourceValues_[2].getAsVector<uint32_t>();

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active) {
            uint64_t addr = n + m[i];
            addresses.push_back({addr, 4});
          }
        }
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_SST1D_IMM: {  // st1d {zt.d}, pg, [zn.d{, #imm}]
        const uint64_t* p = sourceValues_[1].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;

        const uint64_t* n = sourceValues_[2].getAsVector<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[2].mem.disp);

        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(partition_num);

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
      case Opcode::AArch64_ST1Fourv2s_POST: {  // st1 {vt.2s, vt2.2s, vt3.2s,
                                               // vt4.2s}, [xn], <#imm|xm>
        const uint64_t base = sourceValues_[4].get<uint64_t>();
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(4);

        for (int i = 0; i < 4; i++) {
          addresses.push_back({base + (i * 8), 8});
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1Fourv16b:  // st1 {vt.16b, vt2.16b, vt3.16b,
                                         // v42.16b}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Fourv16b_POST:  // st1 {vt.16b, vt3.16b, v42.16b,
                                              // vt2.16b}, [xn], <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_ST1Fourv2d:  // st1 {vt.2d, vt2.2d, vt3.2d, vt4.2d},
                                        // [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Fourv2d_POST:  // st1 {vt.2d, vt3.2d, vt4.2d,
                                             // vt2.2d}, [xn], <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_ST1Fourv4s:  // st1 {vt.4s, vt2.4s, vt3.4s, vt4.4s},
                                        // [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Fourv4s_POST: {  // st1 {vt.4s, vt2.4s, vt3.4s,
                                               // vt4.4s}, [xn], <#imm|xm>
        const uint64_t base = sourceValues_[4].get<uint64_t>();
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(4);

        for (int i = 0; i < 4; i++) {
          addresses.push_back({base + (i * 16), 16});
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1Twov16b:  // st1 {vt.16b, vt2.16b}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Twov16b_POST:  // st1 {vt.16b, vt2.16b}, [xn],
                                             // <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_ST1Twov2d:  // st1 {vt.2d, vt2.2d}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Twov2d_POST:  // st1 {vt.2d, vt2.2d}, [xn],
                                            // <#imm|xm>
        [[fallthrough]];
      case Opcode::AArch64_ST1Twov4s:  // st1 {vt.4s, vt2.4s}, [xn]
        [[fallthrough]];
      case Opcode::AArch64_ST1Twov4s_POST: {  // st1 {vt.4s, vt2.4s}, [xn],
                                              // <#imm|xm>
        const uint64_t base = sourceValues_[2].get<uint64_t>();
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(2);

        for (int i = 0; i < 2; i++) {
          addresses.push_back({base + (i * 16), 16});
        }
        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_ST1i8_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i8: {  // st1 {vt.b}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_ST1i16_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i16: {  // st1 {vt.h}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 2}});
        break;
      }
      case Opcode::AArch64_ST1i32_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i32: {  // st1 {vt.s}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_ST1i64_POST:
        [[fallthrough]];
      case Opcode::AArch64_ST1i64: {  // st1 {vt.d}[index], [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_ST2Twov4s_POST: {  // st2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
        const uint64_t base = sourceValues_[2].get<uint64_t>();
        std::vector<memory::MemoryAccessTarget> addresses;
        addresses.reserve(2);

        for (int i = 0; i < 2; i++) {
          addresses.push_back({base + i * 16, 16});
        }

        setMemoryAddresses(std::move(addresses));
        break;
      }
      case Opcode::AArch64_STLRB: {  // stlrb wt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_STLRW: {  // stlr wt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_STLRX: {  // stlr xt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_STLXRW: {  // stlxr ws, wt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_STLXRX: {  // stlxr ws, xt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_STPDi:      // stp dt1, dt2, [xn, #imm]
      case Opcode::AArch64_STPDpre:    // stp dt1, dt2, [xn, #imm]!
      case Opcode::AArch64_STPQi:      // stp qt1, qt2, [xn, #imm]
      case Opcode::AArch64_STPQpre:    // stp qt1, qt2, [xn, #imm]!
      case Opcode::AArch64_STPSi:      // stp st1, st2, [xn, #imm]
      case Opcode::AArch64_STPSpre:    // stp st1, st2, [xn, #imm]!
      case Opcode::AArch64_STPWi:      // stp wt1, wt2, [xn, #imm]
      case Opcode::AArch64_STPWpre:    // stp wt1, wt2, [xn, #imm]!
      case Opcode::AArch64_STPXi:      // stp xt1, xt2, [xn, #imm]
      case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[2].get<uint64_t>() + metadata_.operands[2].mem.disp,
            2, dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_STPDpost:    // stp dt1, dt2, [xn], #imm
      case Opcode::AArch64_STPQpost:    // stp qt1, qt2, [xn], #imm
      case Opcode::AArch64_STPSpost:    // stp st1, st2, [xn], #imm
      case Opcode::AArch64_STPWpost:    // stp wt1, wt2, [xn], #imm
      case Opcode::AArch64_STPXpost: {  // stp xt1, xt2, [xn], #imm
        std::vector<memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(sourceValues_[2].get<uint64_t>(), 2,
                                    dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_STRBBpost: {  // strb wd, [xn], #imm
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 1}});
        break;
      }
      case Opcode::AArch64_STRBBpre: {  // strb wd, [xn, #imm]!
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_STRBBroW: {  // strb wd,
                                        //  [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 1}});
        break;
      }
      case Opcode::AArch64_STRBBroX: {  // strb wd,
                                        //  [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 1}});
        break;
      }
      case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STRBui:     // str bt, [xn, #imm]
      case Opcode::AArch64_STRBpre:    // str bt, [xn, #imm]!
      case Opcode::AArch64_STRDui:     // str dt, [xn, #imm]
      case Opcode::AArch64_STRDpre:    // str dt, [xn, #imm]!
      case Opcode::AArch64_STRHui:     // str ht, [xn, #imm]
      case Opcode::AArch64_STRHpre:    // str ht, [xn, #imm]!
      case Opcode::AArch64_STRQui:     // str qt, [xn, #imm]
      case Opcode::AArch64_STRQpre:    // str qt, [xn, #imm]!
      case Opcode::AArch64_STRSui:     // str st, [xn, #imm]
      case Opcode::AArch64_STRSpre:    // str st, [xn, #imm]!
      case Opcode::AArch64_STRWui:     // str wt, [xn, #imm]
      case Opcode::AArch64_STRWpre:    // str wt, [xn, #imm]!
      case Opcode::AArch64_STRXui:     // str xt, [xn, #imm]
      case Opcode::AArch64_STRXpre: {  // str xt, [xn, #imm]!
        std::vector<simeng::memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(
            sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
            1, dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_STRBpost:    // str bt, [xn], #imm
      case Opcode::AArch64_STRDpost:    // str dt, [xn], #imm
      case Opcode::AArch64_STRHpost:    // str ht, [xn], #imm
      case Opcode::AArch64_STRQpost:    // str qt, [xn], #imm
      case Opcode::AArch64_STRSpost:    // str st, [xn], #imm
      case Opcode::AArch64_STRWpost:    // str wt, [xn], #imm
      case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
        std::vector<memory::MemoryAccessTarget> addresses;
        generateContiguousAddresses(sourceValues_[1].get<uint64_t>(), 1,
                                    dataSize_, addresses);
        setMemoryAddresses(addresses);
        break;
      }
      case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 2}});
        break;
      }
      case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_STRHHroW: {  // strh wd,
                                        //  [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_STRHHroX: {  // strh wd,
                                        //  [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 2}});
        break;
      }
      case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 16}});
        break;
      }
      case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRWroW: {  // str wd, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 4}});
        break;
      }
      case Opcode::AArch64_STRXroW: {  // str xd, [xn, wm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint32_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend {#amount}}]
        uint64_t offset = extendOffset(sourceValues_[2].get<uint64_t>(),
                                       metadata_.operands[1]);
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>() + offset, 8}});
        break;
      }
      case Opcode::AArch64_STR_PXI: {  // str pt, [xn{, #imm, mul vl}]
        const uint64_t PL_bits = VL_bits / 8;
        const uint16_t partition_num = PL_bits / 8;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[1].mem.disp);

        setMemoryAddresses({base + (offset * partition_num), partition_num});
        break;
      }
      case Opcode::AArch64_STR_ZXI: {  // str zt, [xn{, #imm, mul vl}]
        const uint16_t partition_num = VL_bits / 8;

        const uint64_t base = sourceValues_[1].get<uint64_t>();
        const int64_t offset =
            static_cast<int64_t>(metadata_.operands[1].mem.disp);

        setMemoryAddresses({base + (offset * partition_num), partition_num});
        break;
      }
      case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              1}});
        break;
      }
      case Opcode::AArch64_STURDi: {  // stur dt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              8}});
        break;
      }
      case Opcode::AArch64_STURHHi: {  // sturh wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              2}});
        break;
      }
      case Opcode::AArch64_STURQi: {  // stur qt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              16}});
        break;
      }
      case Opcode::AArch64_STURSi: {  // stur st, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              4}});
        break;
      }
      case Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              4}});
        break;
      }
      case Opcode::AArch64_STURXi: {  // stur xt, [xn, #imm]
        setMemoryAddresses(
            {{sourceValues_[1].get<uint64_t>() + metadata_.operands[1].mem.disp,
              8}});
        break;
      }
      case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
        break;
      }
      case Opcode::AArch64_STXRX: {  // stxr ws, xt, [xn]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 8}});
        break;
      }
      case Opcode::AArch64_SWPLW: {  // swpl ws, wt, [xn|sp]
        setMemoryAddresses({{sourceValues_[1].get<uint64_t>(), 4}});
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
