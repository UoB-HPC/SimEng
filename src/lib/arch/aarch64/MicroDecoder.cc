#include "simeng/arch/aarch64/MicroDecoder.hh"

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void printInfo(Instruction insn, csh capstoneHandle) {
  int i;
  uint8_t access;
  InstructionMetadata metadata = insn.getMetadata();
  std::cout << "====== 0x" << std::hex << unsigned(metadata.encoding[3])
            << unsigned(metadata.encoding[2]) << unsigned(metadata.encoding[1])
            << unsigned(metadata.encoding[0]) << std::dec
            << " === " << metadata.mnemonic << " " << metadata.operandStr
            << " === " << metadata.id << " === " << metadata.opcode
            << " ======" << std::endl;
  std::cout << "Group: " << insn.getGroup() << std::endl;
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

MicroDecoder::MicroDecoder(YAML::Node config)
    : instructionSplit_(config["Core"]["Micro-Operations"].as<bool>()) {}

uint8_t MicroDecoder::decode(const Architecture& architecture,
                             Instruction macroOp, MacroOp& output,
                             csh capstoneHandle) {
  uint8_t num_ops = 1;
  if (!instructionSplit_) {
    output.resize(num_ops);
    output[0] = std::make_shared<Instruction>(macroOp);
  } else {
    InstructionMetadata metadata = macroOp.getMetadata();
    switch (metadata.opcode) {
      case Opcode::AArch64_LDRXpre: {
        // ldr with post-index splits into a load and address-generation
        // micro-op
        num_ops = 2;
        output.resize(num_ops);
        // address generation uop
        cs_arm64 offset_gen_info = {ARM64_CC_INVALID, false, false, 3, {}};
        cs_arm64_op offset_gen_dest = {0,
                                       ARM64_VAS_INVALID,
                                       {ARM64_SFT_INVALID, 0},
                                       ARM64_EXT_INVALID,
                                       ARM64_OP_REG,
                                       {metadata.operands[1].mem.base},
                                       CS_AC_WRITE};
        cs_arm64_op offset_gen_src = offset_gen_dest;
        offset_gen_src.access = CS_AC_READ;
        cs_arm64_op offset_gen_imm = {0,
                                      ARM64_VAS_INVALID,
                                      {ARM64_SFT_INVALID, 0},
                                      ARM64_EXT_INVALID,
                                      ARM64_OP_IMM,
                                      {},
                                      CS_AC_READ};
        offset_gen_imm.imm =
            static_cast<int64_t>(metadata.operands[1].mem.disp);
        offset_gen_info.operands[0] = offset_gen_dest;
        offset_gen_info.operands[1] = offset_gen_src;
        offset_gen_info.operands[2] = offset_gen_imm;
        cs_detail offset_gen_detail = {{}, 0, {}, 0, {}, 0, {}};
        offset_gen_detail.arm64 = offset_gen_info;
        cs_insn offset_gen_insn = {ARM64_INS_ENDING,
                                   0x0,
                                   4,
                                   "",
                                   "micro_offset_gen",
                                   "",
                                   &offset_gen_detail,
                                   MicroOpcode::OFFSET_GEN};
        output[0] = std::make_shared<Instruction>(
            architecture, InstructionMetadata(offset_gen_insn),
            MicroOpInfo({true, false, 0}));
        printInfo(
            Instruction(architecture, InstructionMetadata(offset_gen_insn),
                        MicroOpInfo({true, false, 0})),
            capstoneHandle);
        // ldr uop
        cs_arm64 ldr_info = {ARM64_CC_INVALID, false, false, 2, {}};
        cs_arm64_op ldr_dest = {0,
                                ARM64_VAS_INVALID,
                                {ARM64_SFT_INVALID, 0},
                                ARM64_EXT_INVALID,
                                ARM64_OP_REG,
                                {metadata.operands[0].reg},
                                CS_AC_WRITE};
        cs_arm64_op ldr_addr = {0,
                                ARM64_VAS_INVALID,
                                {ARM64_SFT_INVALID, 0},
                                ARM64_EXT_INVALID,
                                ARM64_OP_MEM,
                                {},
                                CS_AC_WRITE};
        ldr_addr.mem = {metadata.operands[1].mem.base, ARM64_REG_INVALID, 0};
        ldr_info.operands[0] = ldr_dest;
        ldr_info.operands[1] = ldr_addr;
        cs_detail ldr_detail = {{}, 0, {}, 0, {}, 0, {}};
        ldr_detail.arm64 = ldr_info;
        cs_insn ldr_insn = {
            ARM64_INS_ENDING, 0x0, 4,           "",
            "micro_ldr",      "",  &ldr_detail, MicroOpcode::LDR};
        output[1] = std::make_shared<Instruction>(architecture,
                                                  InstructionMetadata(ldr_insn),
                                                  MicroOpInfo({true, true, 1}));
        printInfo(Instruction(architecture, InstructionMetadata(ldr_insn),
                              MicroOpInfo({true, true, 1})),
                  capstoneHandle);
        break;
      }
      default: {
        output.resize(num_ops);
        output[0] = std::make_shared<Instruction>(macroOp);
        break;
      }
    }
  }
  return num_ops;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
