#include "simeng/arch/aarch64/MicroDecoder.hh"

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

std::unordered_map<uint32_t, std::vector<Instruction>>
    MicroDecoder::microDecodeCache;
std::forward_list<InstructionMetadata> MicroDecoder::microMetadataCache;

MicroDecoder::MicroDecoder()
    : instructionSplit_(config::SimInfo::getValue<bool>(
          config::SimInfo::getConfig()["Core"]["Micro-Operations"])) {
  std::ostringstream str;
  str << SIMENG_SOURCE_DIR << "/simengMicroMetadata.out";
  outputFile_.open(str.str(), std::ofstream::out);
  outputFile_.close();
  outputFile_.open(str.str(), std::ofstream::out | std::ofstream::app);
}

MicroDecoder::~MicroDecoder() {
  microDecodeCache.clear();
  microMetadataCache.clear();
}

bool MicroDecoder::detectOverlap(arm64_reg registerA, arm64_reg registerB) {
  // Early checks on equivalent register ISA names
  if (registerA == registerB) return true;
  if ((registerA == ARM64_REG_WZR || registerA == ARM64_REG_XZR) &&
      (registerB == ARM64_REG_WZR || registerB == ARM64_REG_XZR))
    return true;
  if ((registerA == ARM64_REG_WSP || registerA == ARM64_REG_SP) &&
      (registerB == ARM64_REG_WSP || registerB == ARM64_REG_SP))
    return true;

  // Arrays to hold register identifiers
  std::array<arm64_reg, 2> registers = {registerA, registerB};
  std::array<bool, 2> isGP = {false, false};
  std::array<uint8_t, 2> indexes = {0, 0};
  // Get index of each register and whether they are general purpose
  for (int i = 0; i < 2; i++) {
    if (registers[i] == ARM64_REG_FP) {
      isGP[i] = true;
      indexes[i] = 29;
    } else if (registers[i] == ARM64_REG_LR) {
      isGP[i] = true;
      indexes[i] = 30;
    } else {
      arm64_reg base = (arm64_reg)0;
      if (registers[i] >= ARM64_REG_V0) {
        base = ARM64_REG_V0;
      } else if (registers[i] >= ARM64_REG_Z0) {
        base = ARM64_REG_Z0;
      } else if (registers[i] >= ARM64_REG_X0) {
        base = ARM64_REG_X0;
        isGP[i] = true;
      } else if (registers[i] >= ARM64_REG_W0) {
        base = ARM64_REG_W0;
        isGP[i] = true;
      } else if (registers[i] >= ARM64_REG_S0) {
        base = ARM64_REG_S0;
      } else if (registers[i] >= ARM64_REG_Q0) {
        base = ARM64_REG_Q0;
      } else if (registers[i] >= ARM64_REG_P0) {
        base = ARM64_REG_P0;
      } else if (registers[i] >= ARM64_REG_H0) {
        base = ARM64_REG_H0;
      } else if (registers[i] >= ARM64_REG_D0) {
        base = ARM64_REG_D0;
      } else if (registers[i] >= ARM64_REG_B0) {
        base = ARM64_REG_B0;
      }
      indexes[i] = registers[i] - base;
    }
  }

  // If index and register type match, report overlap
  if ((indexes[0] == indexes[1]) && (isGP[0] == isGP[1])) {
    return true;
  }

  return false;
}

uint8_t MicroDecoder::decode(const Architecture& architecture, uint32_t word,
                             const Instruction& macroOp, MacroOp& output,
                             uint64_t addr, csh capstoneHandle) {
  instructionAddress = addr;
  uint8_t num_ops = 1;
  if (!instructionSplit_) {
    // Instruction splitting not enabled so return macro-operation
    output.resize(num_ops);
    output[0] = std::make_shared<Instruction>(macroOp);
  } else {
    // Try and find instruction splitting entry in cache
    auto iter = microDecodeCache.find(word);
    if (iter == microDecodeCache.end()) {
      // Get macro-operation metadata to create micro-operation metadata from
      InstructionMetadata metadata = macroOp.getMetadata();
      std::vector<Instruction> cacheVector;
      uint8_t dataSize = 0;
      arm64_vas vas = arm64_vas::ARM64_VAS_INVALID;
      uint8_t cvt = aarch64::ConvertTypes::INVALID;
      switch (metadata.opcode) {
        case Opcode::AArch64_LDPDi:
        case Opcode::AArch64_LDPQi:
        case Opcode::AArch64_LDPSi: {
          // ldp with immediate offset splits into two load uops
          dataSize = getDataSize(metadata.operands[0]);
          // Reverse the order of the uops if the base memory register is the
          // same as the first destination register (avoids invalid RAW
          // dependency between uops).
          uint8_t orderA = 0;
          uint8_t orderB = 1;
          if (detectOverlap(metadata.operands[0].reg,
                            metadata.operands[2].mem.base)) {
            orderA = 1;
            orderB = 0;
          }
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderA].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderA * dataSize)},
              capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderB].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderB * dataSize)},
              capstoneHandle, true, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPWi:
        case Opcode::AArch64_LDPXi: {
          // ldp with immediate offset splits into two load uops
          dataSize = getDataSize(metadata.operands[0]);
          // Reverse the order of the uops if the base memory register is the
          // same as the first destination register (avoids invalid RAW
          // dependency between uops).
          uint8_t orderA = 0;
          uint8_t orderB = 1;
          if (detectOverlap(metadata.operands[0].reg,
                            metadata.operands[2].mem.base)) {
            orderA = 1;
            orderB = 0;
          }
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderA].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderA * dataSize)},
              capstoneHandle, false, 1, dataSize));
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderB].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderB * dataSize)},
              capstoneHandle, true, 2, dataSize));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPSWi: {
          // ldp with immediate offset splits into two load uops
          dataSize = 4;
          // Reverse the order of the uops if the base memory register is the
          // same as the first destination register (avoids invalid RAW
          // dependency between uops).
          uint8_t orderA = 0;
          uint8_t orderB = 1;
          if (detectOverlap(metadata.operands[0].reg,
                            metadata.operands[2].mem.base)) {
            orderA = 1;
            orderB = 0;
          }
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderA].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderA * dataSize)},
              capstoneHandle, false, 1, dataSize, true));
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[orderB].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + (orderB * dataSize)},
              capstoneHandle, true, 2, dataSize, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPDpost:
        case Opcode::AArch64_LDPQpost:
        case Opcode::AArch64_LDPSpost: {
          // ldp with post offset splits into two loads and an address offset
          // uop
          dataSize = getDataSize(metadata.operands[0]);
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[1].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, false, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[3].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPWpost:
        case Opcode::AArch64_LDPXpost: {
          // ldp with post offset splits into two loads and an address offset
          // uop
          dataSize = getDataSize(metadata.operands[0]);
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[1].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, false, 2, dataSize));
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[3].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPDpre:
        case Opcode::AArch64_LDPQpre:
        case Opcode::AArch64_LDPSpre: {
          // ldp with pre offset splits into an address offset and two load uops
          dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[2].mem.disp, capstoneHandle));
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[1].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, true, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDPWpre:
        case Opcode::AArch64_LDPXpre: {
          // ldp with pre offset splits into an address offset and two load uops
          dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[2].mem.disp, capstoneHandle));
          // ldr uop 0
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // ldr uop 1
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[1].reg,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, true, 2, dataSize));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRBpost:
        case Opcode::AArch64_LDRBBpost:
          dataSize = 1;
        case Opcode::AArch64_LDRHpost:
        case Opcode::AArch64_LDRHHpost:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_LDRDpost:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_LDRSpost:
          dataSize += (dataSize == 0) ? 4 : 0;
        case Opcode::AArch64_LDRQpost: {
          // ldr with post-index splits into a load and an address offset
          // generation micro-op
          dataSize += (dataSize == 0) ? 16 : 0;
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});

          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[2].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRWpost:
        case Opcode::AArch64_LDRXpost: {
          // ldr with post-index splits into a load and an address offset
          // generation micro-op
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[2].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRSBWpost:
          dataSize = 1;
        case Opcode::AArch64_LDRSHWpost:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_LDRSWpost: {
          // ldr with pre-index splits into an address offset generation and
          // load micro-op
          dataSize += (dataSize == 0) ? 4 : 0;
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize, true));
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[2].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRBpre:
        case Opcode::AArch64_LDRBBpre:
          dataSize = 1;
        case Opcode::AArch64_LDRHpre:
        case Opcode::AArch64_LDRHHpre:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_LDRDpre:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_LDRQpre:
          dataSize += (dataSize == 0) ? 16 : 0;
        case Opcode::AArch64_LDRSpre: {
          // ldr with pre-index splits into an address offset generation and
          // load micro-op
          dataSize += (dataSize == 0) ? 4 : 0;
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, true, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRWpre:
        case Opcode::AArch64_LDRXpre: {
          // ldr with pre-index splits into an address offset generation and
          // load micro-op
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, true, 1, dataSize));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRSBWpre:
          dataSize = 1;
        case Opcode::AArch64_LDRSHWpre:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_LDRSWpre: {
          // ldr with pre-index splits into an address offset generation and
          // load micro-op
          dataSize += (dataSize == 0) ? 4 : 0;
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // ldr uop
          cacheVector.push_back(createLdrUop(
              architecture, metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, true, 1, dataSize, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LD1i32: {
          // LD1 single structure splits into an indexed load generation and mov
          // uop
          dataSize = 4;

          // ldr uop
          cacheVector.push_back(createIndexedLdrUop(
              architecture, metadata.operands[0].reg,
              metadata.operands[0].vector_index,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          cacheVector.back().setSequential();

          // mov uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[0].reg,
                           metadata.operands[0].reg, capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({6, 1, {0}});
          cacheVector.back().setSequential();

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPDi:
        case Opcode::AArch64_STPQi:
        case Opcode::AArch64_STPSi: {
          // stp with immediate offset splits into two store address and two
          // store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + dataSize},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPWi:
        case Opcode::AArch64_STPXi: {
          // stp with immediate offset splits into two store address and two
          // store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID,
               metadata.operands[2].mem.disp + dataSize},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPDpost:
        case Opcode::AArch64_STPQpost:
        case Opcode::AArch64_STPSpost: {
          // stp with post-index splits into two store address, two
          // store data, and an address offset uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store1 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[1].reg,
                                            capstoneHandle, false, 2));
          cacheVector.back().setExecutionInfo({1, 1, {0}});
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[3].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPWpost:
        case Opcode::AArch64_STPXpost: {
          // stp with post-index splits into two store address, two
          // store data, and an address offset uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          // store1 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[1].reg,
                                            capstoneHandle, false, 2));
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[3].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPDpre:
        case Opcode::AArch64_STPQpre:
        case Opcode::AArch64_STPSpre: {
          // stp with pre-index splits into an address offset, two store
          // address, and two store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[2].mem.disp, capstoneHandle));
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPWpre:
        case Opcode::AArch64_STPXpre: {
          // stp with pre-index splits into an address offset, two store
          // address, and two store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[2].mem.disp, capstoneHandle));
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 2, dataSize));
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBpost:
        case Opcode::AArch64_STRBBpost:
          dataSize = 1;
        case Opcode::AArch64_STRDpost:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_STRHpost:
        case Opcode::AArch64_STRHHpost:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_STRSpost:
          dataSize += (dataSize == 0) ? 4 : 0;
        case Opcode::AArch64_STRQpost: {
          // str with post-index splits into a store address, store data,
          // and address offset generation uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize += (dataSize == 0) ? 16 : 0;
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[2].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRWpost:
        case Opcode::AArch64_STRXpost: {
          // str with post-index splits into a store address, store data,
          // and address offset generation uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize = getDataSize(metadata.operands[0]);
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[2].imm, capstoneHandle, true));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBpre:
        case Opcode::AArch64_STRBBpre:
          dataSize = 1;
        case Opcode::AArch64_STRDpre:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_STRHpre:
        case Opcode::AArch64_STRHHpre:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_STRSpre:
          dataSize += (dataSize == 0) ? 4 : 0;
        case Opcode::AArch64_STRQpre: {
          // str with pre-index splits into an address offset, store address,
          // generation, and store data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize += (dataSize == 0) ? 16 : 0;
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRWpre:
        case Opcode::AArch64_STRXpre: {
          // str with pre-index splits into an address offset, store address,
          // generation, and store data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0}, {},
              ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBroW:
        case Opcode::AArch64_STRBBroW:
        case Opcode::AArch64_STRBroX:
        case Opcode::AArch64_STRBBroX:
          dataSize = 1;
        case Opcode::AArch64_STRDroW:
        case Opcode::AArch64_STRDroX:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_STRHroW:
        case Opcode::AArch64_STRHHroW:
        case Opcode::AArch64_STRHroX:
        case Opcode::AArch64_STRHHroX:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_STRSroW:
        case Opcode::AArch64_STRSroX:
          dataSize += (dataSize == 0) ? 4 : 0;
        case Opcode::AArch64_STRQroW:
        case Opcode::AArch64_STRQroX: {
          // str with immediate offset splits into a store address and store
          // data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize += (dataSize == 0) ? 16 : 0;
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, metadata.operands[1].mem.index,
               0},
              {metadata.operands[1].shift.type,
               metadata.operands[1].shift.value},
              metadata.operands[1].ext, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRWroW:
        case Opcode::AArch64_STRWroX:
        case Opcode::AArch64_STRXroW:
        case Opcode::AArch64_STRXroX: {
          // str with immediate offset splits into a store address and store
          // data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize = getDataSize(metadata.operands[0]);
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, metadata.operands[1].mem.index,
               0},
              {metadata.operands[1].shift.type,
               metadata.operands[1].shift.value},
              metadata.operands[1].ext, capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBui:
        case Opcode::AArch64_STRBBui:
          dataSize = 1;
        case Opcode::AArch64_STRDui:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_STRHui:
        case Opcode::AArch64_STRHHui:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_STRSui:
          dataSize += (dataSize == 0) ? 4 : 0;
        case Opcode::AArch64_STRQui: {
          // str with immediate offset splits into a store address and store
          // data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize += (dataSize == 0) ? 16 : 0;
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID,
               metadata.operands[1].mem.disp},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRWui:
        case Opcode::AArch64_STRXui: {
          // str with immediate offset splits into a store address and store
          // data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize = getDataSize(metadata.operands[0]);
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID,
               metadata.operands[1].mem.disp},
              {}, ARM64_EXT_INVALID, capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_ST1B:
          dataSize = 1;
        case Opcode::AArch64_ST1D:
          dataSize += (dataSize == 0) ? 8 : 0;
        case Opcode::AArch64_ST1H:
          dataSize += (dataSize == 0) ? 2 : 0;
        case Opcode::AArch64_ST1W: {  // st1d {zt.d}, pg, [xn, xm, lsl #3]
          // sve store st1x (scalar plus scalar) splits into a store address and
          // store data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          dataSize += (dataSize == 0) ? 4 : 0;
          // store address uop
          cacheVector.push_back(createStrUop_predicated(
              architecture,
              {metadata.operands[2].mem.base, metadata.operands[2].mem.index,
               metadata.operands[2].mem.disp},
              metadata.operands[1].reg, capstoneHandle, false, 1, dataSize));
          cacheVector.back().setExecutionInfo({3, 1, {5, 6}});

          // store data uop
          cacheVector.push_back(createSDUop_predicated(
              architecture, metadata.operands[0].reg, metadata.operands[1].reg,
              capstoneHandle, true, 1, dataSize));
          cacheVector.back().setExecutionInfo({1, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_FMLAv1i32_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_1S
                                                      : vas;
        case Opcode::AArch64_FMLAv2i32_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_2S
                                                      : vas;
        case Opcode::AArch64_FMLAv1i64_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_1D
                                                      : vas;
        case Opcode::AArch64_FMLAv2i64_indexed: {
          // To mimic FMLA indexed splitting, we add a mov uop that moves the
          // 3rd src operand to itself before the original FMLA instruction
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_2D
                                                      : vas;
          // mov uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[2].reg,
                           metadata.operands[2].reg, capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({6, 1, {0}});
          cacheVector.back().setSequential();

          // fmla uop
          cacheVector.push_back(createFmlaUop(architecture, metadata, vas,
                                              capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({9, 1, {0, 3}});
          cacheVector.back().setSequential();

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_FMULv1i32_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_1S
                                                      : vas;
        case Opcode::AArch64_FMULv2i32_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_2S
                                                      : vas;
        case Opcode::AArch64_FMULv1i64_indexed:
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_1D
                                                      : vas;
        case Opcode::AArch64_FMULv2i64_indexed: {
          // To mimic FMUL indexed splitting, we add a mov uop that moves the
          // 2nd src operand to itself before the original FMUL instruction
          vas = (vas == arm64_vas::ARM64_VAS_INVALID) ? arm64_vas::ARM64_VAS_2D
                                                      : vas;
          // mov uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[2].reg,
                           metadata.operands[2].reg, capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({6, 1, {0}});
          cacheVector.back().setSequential();

          // fmul uop
          cacheVector.push_back(createFmulUop(architecture, metadata, vas,
                                              capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({9, 1, {0, 3}});
          cacheVector.back().setSequential();

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_FADDPv2i32p: {
          // To mimic FADDP scalar splitting, we add a mov uop that moves the
          // 1st src operand to itself before the original FADDP instruction mov
          // uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[1].reg,
                           metadata.operands[1].reg, capstoneHandle, false, 1));
          cacheVector.back().setExecutionInfo({6, 1, {0}});
          cacheVector.back().setSequential();
          // faddp uop
          cacheVector.push_back(createFaddpUop(
              architecture, metadata, ARM64_VAS_2S, capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({9, 1, {0, 3}});
          cacheVector.back().setSequential();

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_FCVTZSUWSr: {
          // To mimic FCVT* integer flow splitting, we add a mov uop that moves
          // the 1st src operand to itself before the original FCVT* instruction

          // mov uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[1].reg,
                           metadata.operands[1].reg, capstoneHandle, false, 1));
          // Latency is 9+1 to mimic bypass latency of 1
          cacheVector.back().setExecutionInfo({10, 1, {0}});

          // fcvt* uop
          cacheVector.push_back(createFcvtUop(architecture, metadata,
                                              aarch64::ConvertTypes::StoW,
                                              capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({15, 1, {5, 6}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_SCVTFUWDri:
          cvt = aarch64::ConvertTypes::WtoD;
        case Opcode::AArch64_SCVTFUWSri: {
          // To mimic SCVT* integer flow splitting, we add a mov uop that
          // moves the 1st src operand to itself before the original SCVT*
          // instruction

          cvt = (cvt == aarch64::ConvertTypes::INVALID)
                    ? aarch64::ConvertTypes::WtoS
                    : cvt;

          // mov uop
          cacheVector.push_back(
              createMovUop(architecture, metadata.operands[1].reg,
                           metadata.operands[1].reg, capstoneHandle, false, 1));
          // Latency is 1+3 to mimic bypass latency of 3
          cacheVector.back().setExecutionInfo({4, 1, {2}});

          // scvt* uop
          cacheVector.push_back(createScvtUop(architecture, metadata, cvt,
                                              capstoneHandle, true, 2));
          cacheVector.back().setExecutionInfo({9, 1, {0}});

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        default: {
          // No supported splitting for this Instruction so return
          // macro-operation
          output.resize(num_ops);
          output[0] = std::make_shared<Instruction>(macroOp);
          return num_ops;
        }
      }
    }
    // Get the number of micro-operations split into and transfer into passed
    // output vector
    num_ops = iter->second.size();
    output.resize(num_ops);
    for (size_t uop = 0; uop < num_ops; uop++) {
      // printMetadata(iter->second[uop].getMetadata(), capstoneHandle);
      output[uop] = std::make_shared<Instruction>(iter->second[uop]);
    }
    // microDecodeCache.erase(iter);
  }
  return num_ops;
}

cs_detail MicroDecoder::createDefaultDetail(std::vector<OpType> opTypes) {
  cs_arm64 info = default_info;
  cs_detail detail = default_detail;
  info.op_count = opTypes.size();

  for (int op = 0; op < opTypes.size(); op++) {
    info.operands[op] = default_op;
    info.operands[op].access = opTypes[op].access;
    switch (opTypes[op].type) {
      case arm64_op_type::ARM64_OP_REG: {
        info.operands[op].type = ARM64_OP_REG;
        info.operands[op].reg = ARM64_REG_INVALID;
        break;
      }
      case arm64_op_type::ARM64_OP_IMM: {
        info.operands[op].type = ARM64_OP_IMM;
        info.operands[op].imm = 0;
        break;
      }
      case arm64_op_type::ARM64_OP_MEM: {
        info.operands[op].type = ARM64_OP_MEM;
        info.operands[op].mem = {ARM64_REG_INVALID, ARM64_REG_INVALID, 0};
        break;
      }
      case arm64_op_type::ARM64_OP_INVALID:
      case arm64_op_type::ARM64_OP_FP:
      case arm64_op_type::ARM64_OP_CIMM:
      case arm64_op_type::ARM64_OP_REG_MRS:
      case arm64_op_type::ARM64_OP_REG_MSR:
      case arm64_op_type::ARM64_OP_PSTATE:
      case arm64_op_type::ARM64_OP_SYS:
      case arm64_op_type::ARM64_OP_SVCR:
      case arm64_op_type::ARM64_OP_PREFETCH:
      case arm64_op_type::ARM64_OP_BARRIER:
      case arm64_op_type::ARM64_OP_SME_INDEX:
        break;
    }
  }
  detail.arm64 = info;
  return detail;
}

Instruction MicroDecoder::createMovUop(const Architecture& architecture,
                                       arm64_reg base, arm64_reg destination,
                                       csh capstoneHandle, bool lastMicroOp,
                                       int microOpIndex) {
  cs_detail mov_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}});
  mov_detail.arm64.operands[0].reg = base;
  mov_detail.arm64.operands[1].reg = destination;

  cs_insn mov_cs = {
      arm64_insn::ARM64_INS_MOV, 0x0, 4, "", "micro_mov", "", &mov_detail,
      MicroOpcode::MOV};

  InstructionMetadata mov_metadata(mov_cs);
  microMetadataCache.emplace_front(mov_metadata);
  Instruction mov(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::MOV, 0, aarch64::ConvertTypes::INVALID,
                   lastMicroOp, microOpIndex}));
  mov.setExecutionInfo(architecture.getExecutionInfo(mov));
  return mov;
}

Instruction MicroDecoder::createFaddpUop(const Architecture& architecture,
                                         InstructionMetadata metadata,
                                         arm64_vas vas, csh capstoneHandle,
                                         bool lastMicroOp, int microOpIndex) {
  cs_detail faddp_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}});
  faddp_detail.arm64.operands[0].reg = metadata.operands[0].reg;
  faddp_detail.arm64.operands[0].vas = vas;
  faddp_detail.arm64.operands[1].reg = metadata.operands[1].reg;

  cs_insn faddp_cs = {
      arm64_insn::ARM64_INS_FADDP, 0x0, 4, "", "micro_faddp", "", &faddp_detail,
      MicroOpcode::FADDP};

  InstructionMetadata faddp_metadata(faddp_cs);
  microMetadataCache.emplace_front(faddp_metadata);
  Instruction faddp(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::FADDP, 0, aarch64::ConvertTypes::INVALID,
                   lastMicroOp, microOpIndex}));
  faddp.setExecutionInfo(architecture.getExecutionInfo(faddp));
  return faddp;
}

Instruction MicroDecoder::createFcvtUop(const Architecture& architecture,
                                        InstructionMetadata metadata,
                                        uint8_t cvtType, csh capstoneHandle,
                                        bool lastMicroOp, int microOpIndex) {
  cs_detail fcvt_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}});
  fcvt_detail.arm64.operands[0].reg = metadata.operands[0].reg;
  fcvt_detail.arm64.operands[1].reg = metadata.operands[1].reg;

  cs_insn fcvt_cs = {
      arm64_insn::ARM64_INS_FCVT, 0x0, 4, "", "micro_fcvt", "", &fcvt_detail,
      MicroOpcode::FCVT_INT};

  InstructionMetadata fcvt_metadata(fcvt_cs);
  microMetadataCache.emplace_front(fcvt_metadata);
  Instruction fcvt(architecture, microMetadataCache.front(),
                   MicroOpInfo({true, MicroOpcode::FCVT_INT, 0, cvtType,
                                lastMicroOp, microOpIndex}));
  fcvt.setExecutionInfo(architecture.getExecutionInfo(fcvt));
  return fcvt;
}

Instruction MicroDecoder::createFmlaUop(const Architecture& architecture,
                                        InstructionMetadata metadata,
                                        arm64_vas vas, csh capstoneHandle,
                                        bool lastMicroOp, int microOpIndex) {
  cs_detail fmla_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE | CS_AC_READ},
                           {ARM64_OP_REG},
                           {ARM64_OP_REG}});
  fmla_detail.arm64.operands[0].reg = metadata.operands[0].reg;
  fmla_detail.arm64.operands[0].vas = vas;
  fmla_detail.arm64.operands[1].reg = metadata.operands[1].reg;
  fmla_detail.arm64.operands[2].reg = metadata.operands[2].reg;
  fmla_detail.arm64.operands[2].vector_index =
      metadata.operands[2].vector_index;

  cs_insn fmla_cs = {
      arm64_insn::ARM64_INS_FMLA, 0x0, 4, "", "micro_fmla", "", &fmla_detail,
      MicroOpcode::FMLA};

  InstructionMetadata fmla_metadata(fmla_cs);
  microMetadataCache.emplace_front(fmla_metadata);
  Instruction fmla(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::FMLA, 0, aarch64::ConvertTypes::INVALID,
                   lastMicroOp, microOpIndex}));
  fmla.setExecutionInfo(architecture.getExecutionInfo(fmla));
  return fmla;
}

Instruction MicroDecoder::createFmulUop(const Architecture& architecture,
                                        InstructionMetadata metadata,
                                        arm64_vas vas, csh capstoneHandle,
                                        bool lastMicroOp, int microOpIndex) {
  cs_detail fmul_detail = createDefaultDetail(
      {{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}, {ARM64_OP_REG}});
  fmul_detail.arm64.operands[0].reg = metadata.operands[0].reg;
  fmul_detail.arm64.operands[0].vas = vas;
  fmul_detail.arm64.operands[1].reg = metadata.operands[1].reg;
  fmul_detail.arm64.operands[2].reg = metadata.operands[2].reg;
  fmul_detail.arm64.operands[2].vector_index =
      metadata.operands[2].vector_index;

  cs_insn fmul_cs = {
      arm64_insn::ARM64_INS_FMUL, 0x0, 4, "", "micro_fmul", "", &fmul_detail,
      MicroOpcode::FMUL};

  InstructionMetadata fmul_metadata(fmul_cs);
  microMetadataCache.emplace_front(fmul_metadata);
  Instruction fmul(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::FMUL, 0, aarch64::ConvertTypes::INVALID,
                   lastMicroOp, microOpIndex}));
  fmul.setExecutionInfo(architecture.getExecutionInfo(fmul));
  return fmul;
}

Instruction MicroDecoder::createImmOffsetUop(const Architecture& architecture,
                                             arm64_reg base, int64_t offset,
                                             csh capstoneHandle,
                                             bool lastMicroOp,
                                             int microOpIndex) {
  cs_detail off_imm_detail = createDefaultDetail(
      {{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}, {ARM64_OP_IMM}});
  off_imm_detail.arm64.operands[0].reg = base;
  off_imm_detail.arm64.operands[1].reg = base;
  off_imm_detail.arm64.operands[2].imm = offset;

  cs_insn off_imm_cs = {arm64_insn::ARM64_INS_ADD,
                        0x0,
                        4,
                        "",
                        "micro_offset_imm",
                        "",
                        &off_imm_detail,
                        MicroOpcode::OFFSET_IMM};

  InstructionMetadata off_imm_metadata(off_imm_cs);
  microMetadataCache.emplace_front(off_imm_metadata);
  Instruction off_imm(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::OFFSET_IMM, 0,
                   aarch64::ConvertTypes::INVALID, lastMicroOp, microOpIndex}));
  off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
  return off_imm;
}

Instruction MicroDecoder::createLdrUop(const Architecture& architecture,
                                       arm64_reg dest, arm64_op_mem mem,
                                       csh capstoneHandle, bool lastMicroOp,
                                       int microOpIndex, uint8_t dataSize,
                                       bool isSigned) {
  cs_detail ldr_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_MEM}});
  ldr_detail.arm64.operands[0].reg = dest;
  ldr_detail.arm64.operands[1].mem = mem;
  cs_insn ldr_cs = {
      arm64_insn::ARM64_INS_LDR,
      0x0,
      4,
      "",
      "micro_ldr",
      "",
      &ldr_detail,
      (isSigned) ? MicroOpcode::LDRS_ADDR : MicroOpcode::LDR_ADDR};
  InstructionMetadata ldr_metadata(ldr_cs);
  microMetadataCache.emplace_front(ldr_metadata);
  Instruction ldr(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true,
                   (isSigned) ? MicroOpcode::LDRS_ADDR : MicroOpcode::LDR_ADDR,
                   dataSize, aarch64::ConvertTypes::INVALID, lastMicroOp,
                   microOpIndex}));
  ldr.setExecutionInfo(architecture.getExecutionInfo(ldr));
  return ldr;
}

Instruction MicroDecoder::createIndexedLdrUop(
    const Architecture& architecture, arm64_reg dest, int vectorIndex,
    arm64_op_mem mem, csh capstoneHandle, bool lastMicroOp, int microOpIndex,
    uint8_t dataSize) {
  cs_detail ldr_detail = createDefaultDetail(
      {{ARM64_OP_REG, CS_AC_WRITE | CS_AC_READ}, {ARM64_OP_MEM}});
  ldr_detail.arm64.operands[0].reg = dest;
  ldr_detail.arm64.operands[0].vector_index = vectorIndex;
  ldr_detail.arm64.operands[1].mem = mem;
  cs_insn ldr_cs = {
      arm64_insn::ARM64_INS_LDR, 0x0, 4,           "",
      "micro_idx_ldr",           "",  &ldr_detail, MicroOpcode::IDX_LDR_ADDR};
  InstructionMetadata ldr_metadata(ldr_cs);
  microMetadataCache.emplace_front(ldr_metadata);
  Instruction ldr(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::IDX_LDR_ADDR, dataSize,
                   aarch64::ConvertTypes::INVALID, lastMicroOp, microOpIndex}));
  ldr.setExecutionInfo(architecture.getExecutionInfo(ldr));
  return ldr;
}

Instruction MicroDecoder::createScvtUop(const Architecture& architecture,
                                        InstructionMetadata metadata,
                                        uint8_t cvtType, csh capstoneHandle,
                                        bool lastMicroOp, int microOpIndex) {
  cs_detail scvt_detail =
      createDefaultDetail({{ARM64_OP_REG, CS_AC_WRITE}, {ARM64_OP_REG}});
  scvt_detail.arm64.operands[0].reg = metadata.operands[0].reg;
  scvt_detail.arm64.operands[1].reg = metadata.operands[1].reg;

  cs_insn scvt_cs = {
      arm64_insn::ARM64_INS_SCVTF, 0x0, 4, "", "micro_scvt", "", &scvt_detail,
      MicroOpcode::SCVT_INT};

  InstructionMetadata scvt_metadata(scvt_cs);
  microMetadataCache.emplace_front(scvt_metadata);
  Instruction scvt(architecture, microMetadataCache.front(),
                   MicroOpInfo({true, MicroOpcode::SCVT_INT, 0, cvtType,
                                lastMicroOp, microOpIndex}));
  scvt.setExecutionInfo(architecture.getExecutionInfo(scvt));
  return scvt;
}

Instruction MicroDecoder::createSDUop(const Architecture& architecture,
                                      arm64_reg src, csh capstoneHandle,
                                      bool lastMicroOp, int microOpIndex) {
  cs_detail sd_detail = createDefaultDetail({{ARM64_OP_REG}});
  sd_detail.arm64.operands[0].reg = src;
  cs_insn sd_cs = {
      arm64_insn::ARM64_INS_STR, 0x0, 4, "", "micro_sd", "", &sd_detail,
      MicroOpcode::STR_DATA};
  InstructionMetadata sd_metadata(sd_cs);
  microMetadataCache.emplace_front(sd_metadata);
  Instruction sd(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::STR_DATA, 0,
                   aarch64::ConvertTypes::INVALID, lastMicroOp, microOpIndex}));
  sd.setExecutionInfo(architecture.getExecutionInfo(sd));
  return sd;
}

Instruction MicroDecoder::createStrUop(const Architecture& architecture,
                                       arm64_op_mem mem, opShift sft,
                                       arm64_extender ext, csh capstoneHandle,
                                       bool lastMicroOp, int microOpIndex,
                                       uint8_t dataSize) {
  cs_detail str_detail = createDefaultDetail({{ARM64_OP_MEM}});
  str_detail.arm64.operands[0].mem = mem;
  str_detail.arm64.operands[0].ext = ext;
  str_detail.arm64.operands[0].shift = {sft.type, sft.value};
  cs_insn str_cs = {arm64_insn::ARM64_INS_STR,
                    0x0,
                    4,
                    "",
                    "micro_str",
                    "",
                    &str_detail,
                    (mem.index == ARM64_REG_INVALID)
                        ? MicroOpcode::STR_ADDR
                        : MicroOpcode::STR_ADDR_EX};
  InstructionMetadata str_metadata(str_cs);
  microMetadataCache.emplace_front(str_metadata);
  Instruction str(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true,
                   (mem.index == ARM64_REG_INVALID) ? MicroOpcode::STR_ADDR
                                                    : MicroOpcode::STR_ADDR_EX,
                   dataSize, aarch64::ConvertTypes::INVALID, lastMicroOp,
                   microOpIndex}));
  str.setExecutionInfo(architecture.getExecutionInfo(str));
  return str;
}

Instruction MicroDecoder::createSDUop_predicated(
    const Architecture& architecture, arm64_reg src, arm64_reg pred,
    csh capstoneHandle, bool lastMicroOp, int microOpIndex, uint8_t dataSize) {
  cs_detail sd_detail = createDefaultDetail({{ARM64_OP_REG}, {ARM64_OP_REG}});
  sd_detail.arm64.operands[0].reg = src;
  sd_detail.arm64.operands[1].reg = pred;
  cs_insn sd_cs = {
      arm64_insn::ARM64_INS_STR, 0x0, 4,          "",
      "micro_sd_pred",           "",  &sd_detail, MicroOpcode::STR_DATA_PRED};
  InstructionMetadata sd_metadata(sd_cs);
  microMetadataCache.emplace_front(sd_metadata);
  Instruction sd(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::STR_DATA_PRED, dataSize,
                   aarch64::ConvertTypes::INVALID, lastMicroOp, microOpIndex}));
  sd.setExecutionInfo(architecture.getExecutionInfo(sd));
  return sd;
}

Instruction MicroDecoder::createStrUop_predicated(
    const Architecture& architecture, arm64_op_mem mem, arm64_reg pred,
    csh capstoneHandle, bool lastMicroOp, int microOpIndex, uint8_t dataSize) {
  cs_detail str_detail = createDefaultDetail({{ARM64_OP_MEM}, {ARM64_OP_REG}});
  str_detail.arm64.operands[0].mem = mem;
  str_detail.arm64.operands[1].reg = pred;
  cs_insn str_cs = {
      arm64_insn::ARM64_INS_STR, 0x0, 4,           "",
      "micro_str_pred",          "",  &str_detail, MicroOpcode::STR_ADDR_PRED};
  InstructionMetadata str_metadata(str_cs);
  microMetadataCache.emplace_front(str_metadata);
  Instruction str(
      architecture, microMetadataCache.front(),
      MicroOpInfo({true, MicroOpcode::STR_ADDR_PRED, dataSize,
                   aarch64::ConvertTypes::INVALID, lastMicroOp, microOpIndex}));
  str.setExecutionInfo(architecture.getExecutionInfo(str));
  return str;
}

void MicroDecoder::printMetadata(const InstructionMetadata& metadata,
                                 csh capstoneHandle) const {
  int i;
  uint8_t access;
  outputFile_ << "====== 0x" << std::hex << instructionAddress << std::dec
              << " === 0x" << std::hex << unsigned(metadata.encoding[3])
              << unsigned(metadata.encoding[2])
              << unsigned(metadata.encoding[1])
              << unsigned(metadata.encoding[0]) << std::dec
              << " === " << metadata.mnemonic << " " << metadata.operandStr
              << " === " << metadata.id << " === " << metadata.opcode
              << " ======" << std::endl;
  outputFile_ << "Other cs_insn details:" << std::endl;
  outputFile_ << "\tsize = 4" << std::endl;
  outputFile_ << "Other InstructionMetadata details:" << std::endl;
  outputFile_ << "\tgroupCount = " << unsigned(metadata.groupCount)
              << std::endl;
  outputFile_ << "Operands:" << std::endl;
  if (metadata.operandCount)
    outputFile_ << "\top_count: " << unsigned(metadata.operandCount)
                << std::endl;

  for (i = 0; i < metadata.operandCount; i++) {
    cs_arm64_op op = metadata.operands[i];
    switch (op.type) {
      default:
        break;
      case ARM64_OP_REG:
        outputFile_ << "\t\toperands[" << i
                    << "].type: REG = " << cs_reg_name(capstoneHandle, op.reg)
                    << std::endl;
        break;
      case ARM64_OP_IMM:
        outputFile_ << "\t\toperands[" << i << "].type: IMM = 0x%" << std::hex
                    << op.imm << std::dec << std::endl;
        break;
      case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
        // Issue #681: Windows kernel does not support formatting float
        // point
        outputFile_ << "\t\toperands[" << i
                    << "].type: FP = <float_point_unsupported>" << std::endl;
#else
        outputFile_ << "\t\toperands[" << i << "].type: FP = " << op.fp
                    << std::endl;
#endif
        break;
      case ARM64_OP_MEM:
        outputFile_ << "\t\toperands[" << i << "].type: MEM" << std::endl;
        if (op.mem.base != ARM64_REG_INVALID)
          outputFile_ << "\t\t\toperands[" << i << "].mem.base: REG = "
                      << cs_reg_name(capstoneHandle, op.mem.base) << std::endl;
        if (op.mem.index != ARM64_REG_INVALID)
          outputFile_ << "\t\t\toperands[" << i << "].mem.index: REG = "
                      << cs_reg_name(capstoneHandle, op.mem.index) << std::endl;
        if (op.mem.disp != 0)
          outputFile_ << "\t\t\toperands[" << i << "].mem.disp: 0x" << std::hex
                      << op.mem.disp << std::dec << std::endl;

        break;
      case ARM64_OP_CIMM:
        outputFile_ << "\t\toperands[" << i << "].type: C-IMM = " << (int)op.imm
                    << std::endl;
        break;
      case ARM64_OP_REG_MRS:
        outputFile_ << "\t\toperands[" << i << "].type: REG_MRS = 0x"
                    << std::hex << op.reg << std::dec << std::endl;
        break;
      case ARM64_OP_REG_MSR:
        outputFile_ << "\t\toperands[" << i << "].type: REG_MSR = 0x"
                    << std::hex << op.reg << std::dec << std::endl;
        break;
      case ARM64_OP_PSTATE:
        outputFile_ << "\t\toperands[" << i << "].type: PSTATE = 0x" << std::hex
                    << op.pstate << std::dec << std::endl;
        break;
      case ARM64_OP_SYS:
        outputFile_ << "\t\toperands[" << i << "].type: SYS = 0x" << std::hex
                    << op.sys << std::dec << std::endl;
        break;
      case ARM64_OP_PREFETCH:
        outputFile_ << "\t\toperands[" << i << "].type: PREFETCH = 0x"
                    << std::hex << op.prefetch << std::dec << std::endl;
        break;
      case ARM64_OP_BARRIER:
        outputFile_ << "\t\toperands[" << i << "].type: BARRIER = 0x"
                    << std::hex << op.barrier << std::dec << std::endl;
        break;
      case ARM64_OP_SVCR:
        outputFile_ << "\t\toperands[" << i << "].type: SYS = 0x" << std::hex
                    << op.sys << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRSM)
          outputFile_ << "\t\t\toperands[" << i << "].svcr: BIT = SM"
                      << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRZA)
          outputFile_ << "\t\t\toperands[" << i << "].svcr: BIT = ZA"
                      << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRSMZA)
          outputFile_ << "\t\t\toperands[" << i << "].svcr: BIT = SM & ZA"
                      << std::endl;
        break;
      case ARM64_OP_SME_INDEX:
        outputFile_ << "\t\toperands[" << i << "].type: REG = "
                    << cs_reg_name(capstoneHandle, op.sme_index.reg)
                    << std::endl;
        if (op.sme_index.base != ARM64_REG_INVALID)
          outputFile_ << "\t\t\toperands[" << i << "].index.base: REG = "
                      << cs_reg_name(capstoneHandle, op.sme_index.base)
                      << std::endl;
        if (op.sme_index.disp != 0)
          outputFile_ << "\t\t\toperands[" << i << "].index.disp: 0x"
                      << std::hex << op.sme_index.disp << std::dec << std::endl;
        break;
    }

    access = op.access;
    switch (access) {
      default:
        break;
      case CS_AC_READ:
        outputFile_ << "\t\toperands[" << i << "].access: READ" << std::endl;
        break;
      case CS_AC_WRITE:
        outputFile_ << "\t\toperands[" << i << "].access: WRITE" << std::endl;
        break;
      case CS_AC_READ | CS_AC_WRITE:
        outputFile_ << "\t\toperands[" << i << "].access: READ | WRITE"
                    << std::endl;
        break;
    }

    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value)
      outputFile_ << "\t\t\tShift: type = " << op.shift.type
                  << ", value = " << op.shift.value << std::endl;

    if (op.ext != ARM64_EXT_INVALID)
      outputFile_ << "\t\t\tExt: " << op.ext << std::endl;

    if (op.vas != ARM64_VAS_INVALID)
      outputFile_ << "\t\t\tVector Arrangement Specifier: 0x" << std::hex
                  << op.vas << std::dec << std::endl;

    if (op.vector_index != -1)
      outputFile_ << "\t\t\tVector Index: " << op.vector_index << std::endl;
  }

  if (metadata.setsFlags) outputFile_ << "\tUpdate-flags: True" << std::endl;

  if (metadata.writeback) outputFile_ << "\tWrite-back: True" << std::endl;

  if (metadata.cc)
    outputFile_ << "\tCode-condition: " << unsigned(metadata.cc) << std::endl;

  // Print out all registers read by this instruction
  outputFile_ << "\tRegisters read:";
  for (i = 0; i < metadata.implicitSourceCount; i++) {
    outputFile_ << " "
                << cs_reg_name(capstoneHandle, metadata.implicitSources[i]);
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access & CS_AC_READ)
      outputFile_ << " "
                  << cs_reg_name(capstoneHandle, metadata.operands[i].reg);
  }
  outputFile_ << std::endl;
  // Print out all registers written to this instruction
  outputFile_ << "\tRegisters modified:";
  for (i = 0; i < metadata.implicitDestinationCount; i++) {
    outputFile_ << " "
                << cs_reg_name(capstoneHandle,
                               metadata.implicitDestinations[i]);
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access & CS_AC_WRITE)
      outputFile_ << " "
                  << cs_reg_name(capstoneHandle, metadata.operands[i].reg);
  }
  outputFile_ << std::endl;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
