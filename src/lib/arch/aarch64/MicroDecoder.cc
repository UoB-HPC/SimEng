#include "simeng/arch/aarch64/MicroDecoder.hh"

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void printInfo(Instruction& insn, csh capstoneHandle) {
  int i;
  uint8_t access;
  InstructionMetadata metadata = insn.getMetadata();
  std::cout << "====== 0x" << std::hex << unsigned(metadata.encoding[3])
            << unsigned(metadata.encoding[2]) << unsigned(metadata.encoding[1])
            << unsigned(metadata.encoding[0]) << std::dec
            << " === " << metadata.mnemonic << " " << metadata.operandStr
            << " === " << metadata.id << " === " << metadata.opcode
            << " ======" << std::endl;
  std::cout << "Group Information: " << std::endl;
  std::cout << "\tGroup Num: " << insn.getGroup() << std::endl;
  std::cout << "\tisStoreAddress_: " << insn.isStoreAddress() << std::endl;
  std::cout << "\tisStoreData_: " << insn.isStoreData() << std::endl;
  std::cout << "\tisLoad_: " << insn.isLoad() << std::endl;
  std::cout << "\tisBranch_: " << insn.isBranch() << std::endl;
  std::cout << "\tisRET_: " << insn.isRET() << std::endl;
  std::cout << "\tisBL_: " << insn.isBL() << std::endl;
  std::cout << "Operands:" << std::endl;
  if (metadata.operandCount) printf("\top_count: %u\n", metadata.operandCount);

  for (i = 0; i < metadata.operandCount; i++) {
    cs_arm64_op op = metadata.operands[i];
    switch (op.type) {
      default:
        break;
      case ARM64_OP_REG:
        printf("\t\toperands[%u].type: REG = %s\n", i,
               cs_reg_name(capstoneHandle, op.reg));
        break;
      case ARM64_OP_IMM:
        printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op.imm);
        break;
      case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
        // Issue #681: Windows kernel does not support formatting float
        // point
        printf("\t\toperands[%u].type: FP = <float_point_unsupported>\n", i);
#else
        printf("\t\toperands[%u].type: FP = %f\n", i, op.fp);
#endif
        break;
      case ARM64_OP_MEM:
        printf("\t\toperands[%u].type: MEM\n", i);
        if (op.mem.base != ARM64_REG_INVALID)
          printf("\t\t\toperands[%u].mem.base: REG = %s\n", i,
                 cs_reg_name(capstoneHandle, op.mem.base));
        if (op.mem.index != ARM64_REG_INVALID)
          printf("\t\t\toperands[%u].mem.index: REG = %s\n", i,
                 cs_reg_name(capstoneHandle, op.mem.index));
        if (op.mem.disp != 0)
          printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op.mem.disp);

        break;
      case ARM64_OP_CIMM:
        printf("\t\toperands[%u].type: C-IMM = %u\n", i, (int)op.imm);
        break;
      case ARM64_OP_REG_MRS:
        printf("\t\toperands[%u].type: REG_MRS = 0x%x\n", i, op.reg);
        break;
      case ARM64_OP_REG_MSR:
        printf("\t\toperands[%u].type: REG_MSR = 0x%x\n", i, op.reg);
        break;
      case ARM64_OP_PSTATE:
        printf("\t\toperands[%u].type: PSTATE = 0x%x\n", i, op.pstate);
        break;
      case ARM64_OP_SYS:
        printf("\t\toperands[%u].type: SYS = 0x%x\n", i, op.sys);
        break;
      case ARM64_OP_PREFETCH:
        printf("\t\toperands[%u].type: PREFETCH = 0x%x\n", i, op.prefetch);
        break;
      case ARM64_OP_BARRIER:
        printf("\t\toperands[%u].type: BARRIER = 0x%x\n", i, op.barrier);
        break;
    }

    access = op.access;
    switch (access) {
      default:
        break;
      case CS_AC_READ:
        printf("\t\toperands[%u].access: READ\n", i);
        break;
      case CS_AC_WRITE:
        printf("\t\toperands[%u].access: WRITE\n", i);
        break;
      case CS_AC_READ | CS_AC_WRITE:
        printf("\t\toperands[%u].access: READ | WRITE\n", i);
        break;
    }

    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value)
      printf("\t\t\tShift: type = %u, value = %u\n", op.shift.type,
             op.shift.value);

    if (op.ext != ARM64_EXT_INVALID) printf("\t\t\tExt: %u\n", op.ext);

    if (op.vas != ARM64_VAS_INVALID)
      printf("\t\t\tVector Arrangement Specifier: 0x%x\n", op.vas);

    if (op.vector_index != -1)
      printf("\t\t\tVector Index: %u\n", op.vector_index);
  }

  if (metadata.setsFlags) printf("\tUpdate-flags: True\n");

  if (metadata.writeback) printf("\tWrite-back: True\n");

  if (metadata.cc) printf("\tCode-condition: %u\n", metadata.cc);

  // Print out all registers read by this instruction
  printf("\tRegisters read:");
  for (i = 0; i < metadata.implicitSourceCount; i++) {
    printf(" %s", cs_reg_name(capstoneHandle, metadata.implicitSources[i]));
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access == CS_AC_READ)
      printf(" %s", cs_reg_name(capstoneHandle, metadata.operands[i].reg));
  }
  printf("\n");
  // Print out all registers written to this instruction
  printf("\tRegisters modified:");
  for (i = 0; i < metadata.implicitDestinationCount; i++) {
    printf(" %s",
           cs_reg_name(capstoneHandle, metadata.implicitDestinations[i]));
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access == CS_AC_WRITE)
      printf(" %s", cs_reg_name(capstoneHandle, metadata.operands[i].reg));
  }
  printf("\n");
}

uint8_t getDataSize(arm64_reg reg) {
  // Check from top of the range downwards

  // ARM64_REG_V0 -> {end} are vector registers
  if (reg >= ARM64_REG_V0) {
    assert(false && "Vector registers unsupported in macroOp splitting");
    return 0;
  }

  // ARM64_REG_Z0 -> +31 are scalable vector registers (Z) registers
  if (reg >= ARM64_REG_Z0) {
    assert(false && "SVE Z registers unsupported in macroOp splitting");
    return 0;
  }

  // ARM64_REG_X0 -> +28 are 64-bit (X) registers
  if (reg >= ARM64_REG_X0) {
    return 8;
  }

  // ARM64_REG_W0 -> +30 are 32-bit (W) registers
  if (reg >= ARM64_REG_W0) {
    return 4;
  }

  // ARM64_REG_S0 -> +31 are 32-bit arranged (S) neon registers
  if (reg >= ARM64_REG_S0) {
    return 4;
  }

  // ARM64_REG_Q0 -> +31 are 128-bit arranged (Q) neon registers
  if (reg >= ARM64_REG_Q0) {
    return 16;
  }

  // ARM64_REG_P0 -> +15 are 256-bit (P) registers
  if (reg >= ARM64_REG_P0) {
    assert(false && "Predicate registers unsupported in macroOp splitting");
    return 0;
  }

  // ARM64_REG_H0 -> +31 are 16-bit arranged (H) neon registers
  if (reg >= ARM64_REG_H0) {
    return 2;
  }

  // ARM64_REG_D0 -> +31 are 64-bit arranged (D) neon registers
  if (reg >= ARM64_REG_D0) {
    return 8;
  }

  // ARM64_REG_B0 -> +31 are 8-bit arranged (B) neon registers
  if (reg >= ARM64_REG_B0) {
    return 1;
  }

  assert(false && "Failed to find register in macroOp metadata");
  return 0;
}

std::unordered_map<uint32_t, std::vector<Instruction>>
    MicroDecoder::microDecodeCache;
std::forward_list<InstructionMetadata> MicroDecoder::microMetadataCache;

MicroDecoder::MicroDecoder(YAML::Node config)
    : instructionSplit_(config["Core"]["Micro-Operations"].as<bool>()) {}

MicroDecoder::~MicroDecoder() {
  microDecodeCache.clear();
  microMetadataCache.clear();
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
          // ldr uop 0
          cacheVector.push_back(
              createLdrUop(architecture, metadata.operands[0].reg,
                           {metadata.operands[2].mem.base, ARM64_REG_INVALID,
                            metadata.operands[2].mem.disp},
                           capstoneHandle, false, 1, dataSize));
          // ldr uop 1
          cacheVector.push_back(
              createLdrUop(architecture, metadata.operands[1].reg,
                           {metadata.operands[2].mem.base, ARM64_REG_INVALID,
                            metadata.operands[2].mem.disp + dataSize},
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
          uint8_t dataSize = getDataSize(metadata.operands[0].reg);
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
  printInfo(off_imm, capstoneHandle);
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
  printInfo(ldr, capstoneHandle);
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
  printInfo(sd, capstoneHandle);
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
  printInfo(str, capstoneHandle);
  return str;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
