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
        case Opcode::AArch64_LDRXpost: {
          // ldr with post-index splits into a load and an address offset
          // generation micro-op
          // ldr uop
          cs_insn ldr_cs = createLdrUop(
              metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0});
          InstructionMetadata ldr_metadata(ldr_cs);
          microMetadataCache.emplace_front(ldr_metadata);
          Instruction ldr(architecture, microMetadataCache.front(),
                          MicroOpInfo({true, MicroOpcode::LDR_ADDR, false, 1}));
          ldr.setExecutionInfo(architecture.getExecutionInfo(ldr));
          cacheVector.push_back(ldr);
          printInfo(ldr, capstoneHandle);
          // offset generation uop
          cs_insn off_imm_cs = createImmOffsetUop(metadata.operands[1].mem.base,
                                                  metadata.operands[2].imm);
          InstructionMetadata off_imm_metadata(off_imm_cs);
          microMetadataCache.emplace_front(off_imm_metadata);
          Instruction off_imm(
              architecture, microMetadataCache.front(),
              MicroOpInfo({true, MicroOpcode::OFFSET_IMM, true, 0}));
          off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
          cacheVector.push_back(off_imm);
          printInfo(off_imm, capstoneHandle);

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_LDRXpre: {
          // ldr with pre-index splits into an address offset generation and
          // load micro-op
          // offset generation uop
          cs_insn off_imm_cs = createImmOffsetUop(
              metadata.operands[1].mem.base, metadata.operands[1].mem.disp);
          InstructionMetadata off_imm_metadata(off_imm_cs);
          microMetadataCache.emplace_front(off_imm_metadata);
          Instruction off_imm(
              architecture, microMetadataCache.front(),
              MicroOpInfo({true, MicroOpcode::OFFSET_IMM, false, 0}));
          off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
          cacheVector.push_back(off_imm);
          printInfo(off_imm, capstoneHandle);
          // ldr uop
          cs_insn ldr_cs = createLdrUop(
              metadata.operands[0].reg,
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0});
          InstructionMetadata ldr_metadata(ldr_cs);
          microMetadataCache.emplace_front(ldr_metadata);
          Instruction ldr(architecture, microMetadataCache.front(),
                          MicroOpInfo({true, MicroOpcode::LDR_ADDR, true, 1}));
          ldr.setExecutionInfo(architecture.getExecutionInfo(ldr));
          cacheVector.push_back(ldr);
          printInfo(ldr, capstoneHandle);

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRXpost: {
          // str with post-index splits into a store address, address offset
          // generation, and store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1

          // store address uop
          cs_insn str_cs = createStrUop(
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0});
          InstructionMetadata str_metadata(str_cs);
          microMetadataCache.emplace_front(str_metadata);
          Instruction str(architecture, microMetadataCache.front(),
                          MicroOpInfo({true, MicroOpcode::STR_ADDR, false, 1}));
          str.setExecutionInfo(architecture.getExecutionInfo(str));
          cacheVector.push_back(str);
          printInfo(str, capstoneHandle);
          // offset generation uop
          cs_insn off_imm_cs = createImmOffsetUop(metadata.operands[1].mem.base,
                                                  metadata.operands[2].imm);
          InstructionMetadata off_imm_metadata(off_imm_cs);
          microMetadataCache.emplace_front(off_imm_metadata);
          Instruction off_imm(
              architecture, microMetadataCache.front(),
              MicroOpInfo({true, MicroOpcode::OFFSET_IMM, false, 0}));
          off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
          cacheVector.push_back(off_imm);
          printInfo(off_imm, capstoneHandle);
          // store data uop
          cs_insn sd_cs = createSDUop(metadata.operands[0].reg);
          InstructionMetadata sd_metadata(sd_cs);
          microMetadataCache.emplace_front(sd_metadata);
          Instruction sd(architecture, microMetadataCache.front(),
                         MicroOpInfo({true, MicroOpcode::STR_DATA, true, 1}));
          sd.setExecutionInfo(architecture.getExecutionInfo(sd));
          cacheVector.push_back(sd);
          printInfo(sd, capstoneHandle);

          iter = microDecodeCache.try_emplace(word, cacheVector).first;
          break;
        }
        case Opcode::AArch64_STRXpre: {
          // str with pre-index splits into an address offset, store address,
          // generation, and store data uops
          // NOTE: store data and store address uop are paired through their uop
          // index value of 1

          // offset generation uop
          cs_insn off_imm_cs = createImmOffsetUop(
              metadata.operands[1].mem.base, metadata.operands[1].mem.disp);
          InstructionMetadata off_imm_metadata(off_imm_cs);
          microMetadataCache.emplace_front(off_imm_metadata);
          Instruction off_imm(
              architecture, microMetadataCache.front(),
              MicroOpInfo({true, MicroOpcode::OFFSET_IMM, false, 0}));
          off_imm.setExecutionInfo(architecture.getExecutionInfo(off_imm));
          cacheVector.push_back(off_imm);
          printInfo(off_imm, capstoneHandle);
          // store address uop
          cs_insn str_cs = createStrUop(
              {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0});
          InstructionMetadata str_metadata(str_cs);
          microMetadataCache.emplace_front(str_metadata);
          Instruction str(architecture, microMetadataCache.front(),
                          MicroOpInfo({true, MicroOpcode::STR_ADDR, false, 1}));
          str.setExecutionInfo(architecture.getExecutionInfo(str));
          cacheVector.push_back(str);
          printInfo(str, capstoneHandle);
          // store data uop
          cs_insn sd_cs = createSDUop(metadata.operands[0].reg);
          InstructionMetadata sd_metadata(sd_cs);
          microMetadataCache.emplace_front(sd_metadata);
          Instruction sd(architecture, microMetadataCache.front(),
                         MicroOpInfo({true, MicroOpcode::STR_DATA, true, 1}));
          sd.setExecutionInfo(architecture.getExecutionInfo(sd));
          cacheVector.push_back(sd);
          printInfo(sd, capstoneHandle);

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

cs_insn MicroDecoder::createImmOffsetUop(arm64_reg base, int64_t offset) {
  cs_detail off_imm_detail =
      createDefaultDetail({{ARM64_OP_REG, 1}, {ARM64_OP_REG}, {ARM64_OP_IMM}});
  off_imm_detail.arm64.operands[0].reg = base;
  off_imm_detail.arm64.operands[1].reg = base;
  off_imm_detail.arm64.operands[2].imm = offset;

  cs_insn off_imm_insn = {arm64_insn::ARM64_INS_ADD,
                          0x0,
                          4,
                          "",
                          "micro_offset_imm",
                          "",
                          &off_imm_detail,
                          MicroOpcode::OFFSET_IMM};
  return off_imm_insn;
}

cs_insn MicroDecoder::createLdrUop(arm64_reg dest, arm64_op_mem mem) {
  cs_detail ldr_detail =
      createDefaultDetail({{ARM64_OP_REG, 1}, {ARM64_OP_MEM}});
  ldr_detail.arm64.operands[0].reg = dest;
  ldr_detail.arm64.operands[1].mem = mem;
  cs_insn ldr_insn = {
      arm64_insn::ARM64_INS_LDR, 0x0, 4, "", "micro_ldr", "", &ldr_detail,
      MicroOpcode::LDR_ADDR};
  return ldr_insn;
}

cs_insn MicroDecoder::createSDUop(arm64_reg src) {
  cs_detail sd_detail = createDefaultDetail({{ARM64_OP_REG}});
  sd_detail.arm64.operands[0].reg = src;
  cs_insn sd_insn = {
      arm64_insn::ARM64_INS_STR, 0x0, 4, "", "micro_sd", "", &sd_detail,
      MicroOpcode::STR_DATA};
  return sd_insn;
}

cs_insn MicroDecoder::createStrUop(arm64_op_mem mem) {
  cs_detail str_detail = createDefaultDetail({{ARM64_OP_MEM}});
  str_detail.arm64.operands[0].mem = mem;
  cs_insn str_insn = {
      arm64_insn::ARM64_INS_STR, 0x0, 4, "", "micro_str", "", &str_detail,
      MicroOpcode::STR_DATA};
  return str_insn;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
