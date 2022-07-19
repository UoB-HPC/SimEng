#include "simeng/arch/aarch64/MicroDecoder.hh"

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

std::unordered_map<uint32_t, std::vector<Instruction>>
    MicroDecoder::microDecodeCache;
std::forward_list<InstructionMetadata> MicroDecoder::microMetadataCache;

MicroDecoder::MicroDecoder(YAML::Node config)
    : instructionSplit_(config["Core"]["Micro-Operations"].as<bool>()) {}

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
                             Instruction macroOp, MacroOp& output,
                             csh capstoneHandle) {
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
      switch (metadata.opcode) {
        case Opcode::AArch64_LDPDi:
        case Opcode::AArch64_LDPQi:
        case Opcode::AArch64_LDPSi:
        case Opcode::AArch64_LDPWi:
        case Opcode::AArch64_LDPXi: {
          // ldp with immediate offset splits into two load uops
          uint8_t dataSize = getDataSize(metadata.operands[0]);
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
        case Opcode::AArch64_LDPDpost:
        case Opcode::AArch64_LDPQpost:
        case Opcode::AArch64_LDPSpost:
        case Opcode::AArch64_LDPWpost:
        case Opcode::AArch64_LDPXpost: {
          // ldp with post offset splits into two loads and an address offset
          // uop
          uint8_t dataSize = getDataSize(metadata.operands[0]);
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
        case Opcode::AArch64_LDPSpre:
        case Opcode::AArch64_LDPWpre:
        case Opcode::AArch64_LDPXpre: {
          // ldp with pre offset splits into an address offset and two load uops
          uint8_t dataSize = getDataSize(metadata.operands[0]);
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
        case Opcode::AArch64_LDRDpost:
        case Opcode::AArch64_LDRHpost:
        case Opcode::AArch64_LDRQpost:
        case Opcode::AArch64_LDRSpost:
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
        case Opcode::AArch64_LDRBpre:
        case Opcode::AArch64_LDRDpre:
        case Opcode::AArch64_LDRHpre:
        case Opcode::AArch64_LDRQpre:
        case Opcode::AArch64_LDRSpre:
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
        case Opcode::AArch64_STPDi:
        case Opcode::AArch64_STPQi:
        case Opcode::AArch64_STPSi:
        case Opcode::AArch64_STPWi:
        case Opcode::AArch64_STPXi: {
          // stp with immediate offset splits into two store address and two
          // store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(
              createStrUop(architecture,
                           {metadata.operands[2].mem.base, ARM64_REG_INVALID,
                            metadata.operands[2].mem.disp},
                           capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(
              createStrUop(architecture,
                           {metadata.operands[2].mem.base, ARM64_REG_INVALID,
                            metadata.operands[2].mem.disp + dataSize},
                           capstoneHandle, false, 2, dataSize));
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STPDpost:
        case Opcode::AArch64_STPQpost:
        case Opcode::AArch64_STPSpost:
        case Opcode::AArch64_STPWpost:
        case Opcode::AArch64_STPXpost: {
          // stp with post-index splits into two store address, two
          // store data, and an address offset uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, false, 2, dataSize));
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
        case Opcode::AArch64_STPSpre:
        case Opcode::AArch64_STPWpre:
        case Opcode::AArch64_STPXpre: {
          // stp with pre-index splits into an address offset, two store
          // address, and two store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1 and 2
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[2].mem.base,
              metadata.operands[2].mem.disp, capstoneHandle));
          // store0 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // store0 data uop
          cacheVector.push_back(createSDUop(architecture,
                                            metadata.operands[0].reg,
                                            capstoneHandle, false, 1));
          // store1 address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[2].mem.base, ARM64_REG_INVALID, dataSize},
              capstoneHandle, false, 2, dataSize));
          // store1 data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[1].reg, capstoneHandle, true, 2));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBpost:
        case Opcode::AArch64_STRDpost:
        case Opcode::AArch64_STRHpost:
        case Opcode::AArch64_STRSpost:
        case Opcode::AArch64_STRQpost:
        case Opcode::AArch64_STRWpost:
        case Opcode::AArch64_STRXpost: {
          // str with post-index splits into a store address, store data,
          // and address offset generation uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
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
        case Opcode::AArch64_STRDpre:
        case Opcode::AArch64_STRHpre:
        case Opcode::AArch64_STRSpre:
        case Opcode::AArch64_STRQpre:
        case Opcode::AArch64_STRWpre:
        case Opcode::AArch64_STRXpre: {
          // str with pre-index splits into an address offset, store address,
          // generation, and store data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // offset generation uop
          cacheVector.push_back(createImmOffsetUop(
              architecture, metadata.operands[1].mem.base,
              metadata.operands[1].mem.disp, capstoneHandle));
          // store address uop
          cacheVector.push_back(createStrUop(
              architecture,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0},
              capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRBui:
        case Opcode::AArch64_STRDui:
        case Opcode::AArch64_STRHui:
        case Opcode::AArch64_STRSui:
        case Opcode::AArch64_STRQui:
        case Opcode::AArch64_STRWui:
        case Opcode::AArch64_STRXui: {
          // str with immediate offset splits into a store address and store
          // data uop
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1
          uint8_t dataSize = getDataSize(metadata.operands[0]);
          // store address uop
          cacheVector.push_back(
              createStrUop(architecture,
                           {metadata.operands[1].mem.base, ARM64_REG_INVALID,
                            metadata.operands[1].mem.disp},
                           capstoneHandle, false, 1, dataSize));
          // store data uop
          cacheVector.push_back(createSDUop(
              architecture, metadata.operands[0].reg, capstoneHandle, true, 1));

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
      output[uop] = std::make_shared<Instruction>(iter->second[uop]);
    }
  }
  return num_ops;
}

cs_detail MicroDecoder::createDefaultDetail(std::vector<OpType> opTypes) {
  cs_arm64 info = default_info;
  cs_detail detail = default_detail;
  info.op_count = opTypes.size();

  for (int op = 0; op < opTypes.size(); op++) {
    info.operands[op] = default_op;
    switch (opTypes[op].type) {
      case arm64_op_type::ARM64_OP_REG: {
        info.operands[op].type = ARM64_OP_REG;
        info.operands[op].reg = ARM64_REG_INVALID;
        if (opTypes[op].isDestination) {
          info.operands[op].access = CS_AC_WRITE;
        }
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
        break;
    }
  }
  detail.arm64 = info;
  return detail;
}

Instruction MicroDecoder::createImmOffsetUop(const Architecture& architecture,
                                             arm64_reg base, int64_t offset,
                                             csh capstoneHandle,
                                             bool lastMicroOp,
                                             int microOpIndex) {
  cs_detail off_imm_detail =
      createDefaultDetail({{ARM64_OP_REG, 1}, {ARM64_OP_REG}, {ARM64_OP_IMM}});
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
  Instruction off_imm(architecture, microMetadataCache.front(),
                      MicroOpInfo({true, MicroOpcode::OFFSET_IMM, 0,
                                   lastMicroOp, microOpIndex}));
  off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
  return off_imm;
}

Instruction MicroDecoder::createLdrUop(const Architecture& architecture,
                                       arm64_reg dest, arm64_op_mem mem,
                                       csh capstoneHandle, bool lastMicroOp,
                                       int microOpIndex, uint8_t dataSize) {
  cs_detail ldr_detail =
      createDefaultDetail({{ARM64_OP_REG, 1}, {ARM64_OP_MEM}});
  ldr_detail.arm64.operands[0].reg = dest;
  ldr_detail.arm64.operands[1].mem = mem;
  cs_insn ldr_cs = {
      arm64_insn::ARM64_INS_LDR, 0x0, 4, "", "micro_ldr", "", &ldr_detail,
      MicroOpcode::LDR_ADDR};
  InstructionMetadata ldr_metadata(ldr_cs);
  microMetadataCache.emplace_front(ldr_metadata);
  Instruction ldr(architecture, microMetadataCache.front(),
                  MicroOpInfo({true, MicroOpcode::LDR_ADDR, dataSize,
                               lastMicroOp, microOpIndex}));
  ldr.setExecutionInfo(architecture.getExecutionInfo(ldr));
  return ldr;
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
      MicroOpInfo({true, MicroOpcode::STR_DATA, 0, lastMicroOp, microOpIndex}));
  sd.setExecutionInfo(architecture.getExecutionInfo(sd));
  return sd;
}

Instruction MicroDecoder::createStrUop(const Architecture& architecture,
                                       arm64_op_mem mem, csh capstoneHandle,
                                       bool lastMicroOp, int microOpIndex,
                                       uint8_t dataSize) {
  cs_detail str_detail = createDefaultDetail({{ARM64_OP_MEM}});
  str_detail.arm64.operands[0].mem = mem;
  cs_insn str_cs = {
      arm64_insn::ARM64_INS_STR, 0x0, 4, "", "micro_str", "", &str_detail,
      MicroOpcode::STR_DATA};
  InstructionMetadata str_metadata(str_cs);
  microMetadataCache.emplace_front(str_metadata);
  Instruction str(architecture, microMetadataCache.front(),
                  MicroOpInfo({true, MicroOpcode::STR_ADDR, dataSize,
                               lastMicroOp, microOpIndex}));
  str.setExecutionInfo(architecture.getExecutionInfo(str));
  return str;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
