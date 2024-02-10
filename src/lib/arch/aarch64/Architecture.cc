#include <algorithm>
#include <cassert>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

Architecture::Architecture(kernel::Linux& kernel, ryml::ConstNodeRef config)
    : arch::Architecture(kernel),
      microDecoder_(std::make_unique<MicroDecoder>()),
      VL_(config["Core"]["Vector-Length"].as<uint64_t>()),
      SVL_(config["Core"]["Streaming-Vector-Length"].as<uint64_t>()),
      vctModulo_((config["Core"]["Clock-Frequency-GHz"].as<float>() * 1e9) /
                 (config["Core"]["Timer-Frequency-MHz"].as<uint32_t>() * 1e6)) {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle_) != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle"
              << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle_, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
  std::vector<uint64_t> sysRegs = config::SimInfo::getSysRegVec();
  for (size_t i = 0; i < sysRegs.size(); i++) {
    systemRegisterMap_[sysRegs[i]] = systemRegisterMap_.size();
  }

  // Get Virtual Counter Timer and Processor Cycle Counter system registers.
  VCTreg_ = {
      RegisterType::SYSTEM,
      static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_CNTVCT_EL0))};
  PCCreg_ = {
      RegisterType::SYSTEM,
      static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_PMCCNTR_EL0))};

  // Instantiate an ExecutionInfo entry for each group in the
  // InstructionGroup namespace.
  for (int i = 0; i < NUM_GROUPS; i++) {
    groupExecutionInfo_[i] = {1, 1, {}};
  }
  // Extract execution latency/throughput for each group
  std::vector<uint8_t> inheritanceDistance(NUM_GROUPS, UINT8_MAX);
  for (size_t i = 0; i < config["Latencies"].num_children(); i++) {
    ryml::ConstNodeRef port_node = config["Latencies"][i];
    uint16_t latency = port_node["Execution-Latency"].as<uint16_t>();
    uint16_t throughput = port_node["Execution-Throughput"].as<uint16_t>();
    for (size_t j = 0; j < port_node["Instruction-Group-Nums"].num_children();
         j++) {
      uint16_t group = port_node["Instruction-Group-Nums"][j].as<uint16_t>();
      groupExecutionInfo_[group].latency = latency;
      groupExecutionInfo_[group].stallCycles = throughput;
      // Set zero inheritance distance for latency assignment as it's
      // explicitly defined
      inheritanceDistance[group] = 0;
      // Add inherited support for those appropriate groups
      std::queue<uint16_t> groups;
      groups.push(group);
      // Set a distance counter as 1 to represent 1 level of inheritance
      uint8_t distance = 1;
      while (groups.size()) {
        // Determine if there's any inheritance
        if (groupInheritance_.find(groups.front()) != groupInheritance_.end()) {
          std::vector<uint16_t> inheritedGroups =
              groupInheritance_.at(groups.front());
          for (int k = 0; k < inheritedGroups.size(); k++) {
            // Determine if this group has inherited latency values from a
            // smaller distance
            if (inheritanceDistance[inheritedGroups[k]] > distance) {
              groupExecutionInfo_[inheritedGroups[k]].latency = latency;
              groupExecutionInfo_[inheritedGroups[k]].stallCycles = throughput;
              inheritanceDistance[inheritedGroups[k]] = distance;
            }
            groups.push(inheritedGroups[k]);
          }
        }
        groups.pop();
        distance++;
      }
    }
    // Store any opcode-based latency override
    for (size_t j = 0; j < port_node["Instruction-Opcodes"].num_children();
         j++) {
      uint16_t opcode = port_node["Instruction-Opcodes"][j].as<uint16_t>();
      opcodeExecutionInfo_[opcode].latency = latency;
      opcodeExecutionInfo_[opcode].stallCycles = throughput;
    }
  }

  // ports entries in the groupExecutionInfo_ entries only apply for models
  // using the outoforder core archetype
  if (config::SimInfo::getSimMode() == config::SimulationMode::Outoforder) {
    // Create mapping between instructions groups and the ports that support
    // them
    for (size_t i = 0; i < config["Ports"].num_children(); i++) {
      // Store which ports support which groups
      ryml::ConstNodeRef group_node =
          config["Ports"][i]["Instruction-Group-Support-Nums"];
      for (size_t j = 0; j < group_node.num_children(); j++) {
        uint16_t group = group_node[j].as<uint16_t>();
        uint16_t newPort = static_cast<uint16_t>(i);
        groupExecutionInfo_[group].ports.push_back(newPort);
        // Add inherited support for those appropriate groups
        std::queue<uint16_t> groups;
        groups.push(group);
        while (groups.size()) {
          // Determine if there's any inheritance
          if (groupInheritance_.find(groups.front()) !=
              groupInheritance_.end()) {
            std::vector<uint16_t> inheritedGroups =
                groupInheritance_.at(groups.front());
            for (int k = 0; k < inheritedGroups.size(); k++) {
              groupExecutionInfo_[inheritedGroups[k]].ports.push_back(newPort);
              groups.push(inheritedGroups[k]);
            }
          }
          groups.pop();
        }
      }
      // Store any opcode-based port support override
      ryml::ConstNodeRef opcode_node =
          config["Ports"][i]["Instruction-Opcode-Support"];
      for (size_t j = 0; j < opcode_node.num_children(); j++) {
        // If latency information hasn't been defined, set to zero as to
        // inform later access to use group defined latencies instead
        uint16_t opcode = opcode_node[j].as<uint16_t>();
        opcodeExecutionInfo_.try_emplace(opcode, ExecutionInfo{0, 0, {}});
        opcodeExecutionInfo_[opcode].ports.push_back(static_cast<uint8_t>(i));
      }
    }
  }
}

Architecture::~Architecture() { cs_close(&capstoneHandle_); }

uint8_t Architecture::predecode(const void* ptr, uint16_t bytesAvailable,
                                uint64_t instructionAddress,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv9.2-a
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache_.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache_.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    // Return non-zero value to avoid fatal error
    return 1;
  }

  assert(bytesAvailable >= 4 &&
         "Fewer than 4 bytes supplied to AArch64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  // `ptr` is not guaranteed to be aligned.
  uint32_t insn;
  memcpy(&insn, ptr, 4);

  // Try to find the decoding in the decode cache
  auto iter = decodeCache_.find(insn);
  if (iter == decodeCache_.end()) {
    // No decoding present. Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

    bool success =
        cs_disasm_iter(capstoneHandle_, &encoding, &size, &address, &rawInsn);

    auto metadata =
        success ? InstructionMetadata(rawInsn) : InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache_.push_front(metadata);
    if (instructionAddress >= 0) {
      int i;
      uint8_t access;
      std::cerr << "====== 0x" << std::hex << instructionAddress << std::dec
                << " === 0x" << std::hex << unsigned(metadata.encoding[3])
                << unsigned(metadata.encoding[2])
                << unsigned(metadata.encoding[1])
                << unsigned(metadata.encoding[0]) << std::dec
                << " === " << metadata.mnemonic << " " << metadata.operandStr
                << " === " << metadata.id << " === " << metadata.opcode
                << " ======" << std::endl;
      std::cerr << "Other cs_insn details:" << std::endl;
      std::cerr << "\taddress = " << rawInsn.address << std::endl;
      std::cerr << "\tsize = " << rawInsn.size << std::endl;
      std::cerr << "Other InstructionMetadata details:" << std::endl;
      std::cerr << "\tgroupCount = " << unsigned(metadata.groupCount)
                << std::endl;
      std::cerr << "Operands:" << std::endl;
      if ((&rawInsn)->detail != NULL) {
        if (metadata.operandCount)
          fprintf(stderr, "\top_count: %u\n", metadata.operandCount);

        for (i = 0; i < metadata.operandCount; i++) {
          cs_arm64_op op = metadata.operands[i];
          switch (op.type) {
            default:
              break;
            case ARM64_OP_REG:
              fprintf(stderr, "\t\toperands[%u].type: REG = %s\n", i,
                      cs_reg_name(capstoneHandle, op.reg));
              break;
            case ARM64_OP_IMM:
              fprintf(stderr, "\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i,
                      op.imm);
              break;
            case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
              // Issue #681: Windows kernel does not support formatting float
              // point
              fprintf(stderr,
                      "\t\toperands[%u].type: FP = <float_point_unsupported>\n",
                      i);
#else
              fprintf(stderr, "\t\toperands[%u].type: FP = %f\n", i, op.fp);
#endif
              break;
            case ARM64_OP_MEM:
              fprintf(stderr, "\t\toperands[%u].type: MEM\n", i);
              if (op.mem.base != ARM64_REG_INVALID)
                fprintf(stderr, "\t\t\toperands[%u].mem.base: REG = %s\n", i,
                        cs_reg_name(capstoneHandle, op.mem.base));
              if (op.mem.index != ARM64_REG_INVALID)
                fprintf(stderr, "\t\t\toperands[%u].mem.index: REG = %s\n", i,
                        cs_reg_name(capstoneHandle, op.mem.index));
              if (op.mem.disp != 0)
                fprintf(stderr, "\t\t\toperands[%u].mem.disp: 0x%x\n", i,
                        op.mem.disp);

              break;
            case ARM64_OP_CIMM:
              fprintf(stderr, "\t\toperands[%u].type: C-IMM = %u\n", i,
                      (int)op.imm);
              break;
            case ARM64_OP_REG_MRS:
              fprintf(stderr, "\t\toperands[%u].type: REG_MRS = 0x%x\n", i,
                      op.reg);
              break;
            case ARM64_OP_REG_MSR:
              fprintf(stderr, "\t\toperands[%u].type: REG_MSR = 0x%x\n", i,
                      op.reg);
              break;
            case ARM64_OP_PSTATE:
              fprintf(stderr, "\t\toperands[%u].type: PSTATE = 0x%x\n", i,
                      op.pstate);
              break;
            case ARM64_OP_SYS:
              fprintf(stderr, "\t\toperands[%u].type: SYS = 0x%x\n", i, op.sys);
              break;
            case ARM64_OP_PREFETCH:
              fprintf(stderr, "\t\toperands[%u].type: PREFETCH = 0x%x\n", i,
                      op.prefetch);
              break;
            case ARM64_OP_BARRIER:
              fprintf(stderr, "\t\toperands[%u].type: BARRIER = 0x%x\n", i,
                      op.barrier);
              break;
            case ARM64_OP_SVCR:
              fprintf(stderr, "\t\toperands[%u].type: SYS = 0x%x\n", i, op.sys);
              if (op.svcr == ARM64_SVCR_SVCRSM)
                fprintf(stderr, "\t\t\toperands[%u].svcr: BIT = SM\n", i);
              if (op.svcr == ARM64_SVCR_SVCRZA)
                fprintf(stderr, "\t\t\toperands[%u].svcr: BIT = ZA\n", i);
              if (op.svcr == ARM64_SVCR_SVCRSMZA)
                fprintf(stderr, "\t\t\toperands[%u].svcr: BIT = SM & ZA\n", i);
              break;
            case ARM64_OP_SME_INDEX:
              fprintf(stderr, "\t\toperands[%u].type: REG = %s\n", i,
                      cs_reg_name(capstoneHandle, op.sme_index.reg));
              if (op.sme_index.base != ARM64_REG_INVALID)
                fprintf(stderr, "\t\t\toperands[%u].index.base: REG = %s\n", i,
                        cs_reg_name(capstoneHandle, op.sme_index.base));
              if (op.sme_index.disp != 0)
                fprintf(stderr, "\t\t\toperands[%u].index.disp: 0x%x\n", i,
                        op.sme_index.disp);
              break;
          }

          access = op.access;
          switch (access) {
            default:
              break;
            case CS_AC_READ:
              fprintf(stderr, "\t\toperands[%u].access: READ\n", i);
              break;
            case CS_AC_WRITE:
              fprintf(stderr, "\t\toperands[%u].access: WRITE\n", i);
              break;
            case CS_AC_READ | CS_AC_WRITE:
              fprintf(stderr, "\t\toperands[%u].access: READ | WRITE\n", i);
              break;
          }

          if (op.shift.type != ARM64_SFT_INVALID && op.shift.value)
            fprintf(stderr, "\t\t\tShift: type = %u, value = %u\n",
                    op.shift.type, op.shift.value);

          if (op.ext != ARM64_EXT_INVALID)
            fprintf(stderr, "\t\t\tExt: %u\n", op.ext);

          if (op.vas != ARM64_VAS_INVALID)
            fprintf(stderr, "\t\t\tVector Arrangement Specifier: 0x%x\n",
                    op.vas);

          if (op.vector_index != -1)
            fprintf(stderr, "\t\t\tVector Index: %u\n", op.vector_index);
        }

        if (metadata.setsFlags) fprintf(stderr, "\tUpdate-flags: True\n");

        if (metadata.writeback) fprintf(stderr, "\tWrite-back: True\n");

        if (metadata.cc) fprintf(stderr, "\tCode-condition: %u\n", metadata.cc);

        // Print out all registers read by this instruction
        fprintf(stderr, "\tRegisters read:");
        for (i = 0; i < metadata.implicitSourceCount; i++) {
          fprintf(stderr, " %s",
                  cs_reg_name(capstoneHandle, metadata.implicitSources[i]));
        }
        for (i = 0; i < metadata.operandCount; i++) {
          if (metadata.operands[i].type == ARM64_OP_REG &&
              metadata.operands[i].access & CS_AC_READ)
            fprintf(stderr, " %s",
                    cs_reg_name(capstoneHandle, metadata.operands[i].reg));
        }
        fprintf(stderr, "\n");
        // Print out all registers written to this instruction
        fprintf(stderr, "\tRegisters modified:");
        for (i = 0; i < metadata.implicitDestinationCount; i++) {
          fprintf(
              stderr, " %s",
              cs_reg_name(capstoneHandle, metadata.implicitDestinations[i]));
        }
        for (i = 0; i < metadata.operandCount; i++) {
          if (metadata.operands[i].type == ARM64_OP_REG &&
              metadata.operands[i].access & CS_AC_WRITE)
            fprintf(stderr, " %s",
                    cs_reg_name(capstoneHandle, metadata.operands[i].reg));
        }
        fprintf(stderr, "\n");
      }
    }

    // Create an instruction using the metadata
    Instruction newInsn(*this, metadataCache_.front(), MicroOpInfo());
    // Set execution information for this instruction
    newInsn.setExecutionInfo(getExecutionInfo(newInsn));
    // Cache the instruction
    iter = decodeCache_.insert({insn, newInsn}).first;
  }

  // Split instruction into 1 or more defined micro-ops
  uint8_t num_ops = microDecoder_->decode(*this, iter->first, iter->second,
                                          output, capstoneHandle_);

  // Set instruction address and branch prediction for each micro-op generated
  for (int i = 0; i < num_ops; i++) {
    output[i]->setInstructionAddress(instructionAddress);
  }

  return 4;
}

int32_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  // Check below is done for speculative instructions that may be passed into
  // the function but will not be executed. If such invalid speculative
  // instructions get through they can cause an out-of-range error.
  if (!systemRegisterMap_.count(reg)) return -1;
  return systemRegisterMap_.at(reg);
}

std::shared_ptr<arch::ExceptionHandler> Architecture::handleException(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    memory::MemoryInterface& memory) const {
  return std::make_shared<ExceptionHandler>(instruction, core, memory, linux_);
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type
  changes.type = ChangeType::REPLACEMENT;

  uint64_t stackPointer = linux_.getInitialStackPointer();
  // Set the stack pointer register
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 31});
  changes.modifiedRegisterValues.push_back(stackPointer);

  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM,
       static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0))});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(0b10100));

  return changes;
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint8_t Architecture::getMinInstructionSize() const { return 4; }

void Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  // Update the Processor Cycle Counter to total cycles completed.
  regFile->set(PCCreg_, iterations);
  // Update Virtual Counter Timer at correct frequency.
  if (iterations % (uint64_t)vctModulo_ == 0) {
    regFile->set(VCTreg_, regFile->get(VCTreg_).get<uint64_t>() + 1);
  }
}

ExecutionInfo Architecture::getExecutionInfo(const Instruction& insn) const {
  // Assume no opcode-based override
  ExecutionInfo exeInfo = groupExecutionInfo_.at(insn.getGroup());
  if (opcodeExecutionInfo_.find(insn.getMetadata().opcode) !=
      opcodeExecutionInfo_.end()) {
    // Replace with overrided values
    ExecutionInfo overrideInfo =
        opcodeExecutionInfo_.at(insn.getMetadata().opcode);
    if (overrideInfo.latency != 0) exeInfo.latency = overrideInfo.latency;
    if (overrideInfo.stallCycles != 0)
      exeInfo.stallCycles = overrideInfo.stallCycles;
    if (overrideInfo.ports.size()) exeInfo.ports = overrideInfo.ports;
  }
  return exeInfo;
}

uint64_t Architecture::getVectorLength() const { return VL_; }

uint64_t Architecture::getStreamingVectorLength() const { return SVL_; }

/** The SVCR value is stored in Architecture to allow the value to be
 * retrieved within execution pipeline. This prevents adding an implicit
 * operand to every SME instruction; reducing the amount of complexity when
 * implementing SME execution logic. */
uint64_t Architecture::getSVCRval() const { return SVCRval_; }

void Architecture::setSVCRval(const uint64_t newVal) const {
  SVCRval_ = newVal;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
