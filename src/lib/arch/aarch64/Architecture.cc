#include <algorithm>
#include <cassert>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void printMetadata(Instruction& insn, csh capstoneHandle) {
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

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;

Architecture::Architecture(kernel::Linux& kernel, YAML::Node config)
    : linux_(kernel),
      microDecoder_(std::make_unique<MicroDecoder>(config)),
      VL_(config["Core"]["Vector-Length"].as<uint64_t>()) {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "Could not create capstone handle" << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
  systemRegisterMap_[ARM64_SYSREG_DCZID_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FPCR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FPSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTVCT_EL0] = systemRegisterMap_.size();

  // Instantiate an ExecutionInfo entry for each group in the InstructionGroup
  // namespace.
  for (int i = 0; i < NUM_GROUPS; i++) {
    groupExecutionInfo_[i] = {1, 1, {}};
  }
  // Extract execution latency/throughput for each group
  std::vector<uint8_t> inheritanceDistance(NUM_GROUPS, UINT8_MAX);
  for (size_t i = 0; i < config["Latencies"].size(); i++) {
    YAML::Node port_node = config["Latencies"][i];
    uint16_t latency = port_node["Execution-Latency"].as<uint16_t>();
    uint16_t throughput = port_node["Execution-Throughput"].as<uint16_t>();
    for (size_t j = 0; j < port_node["Instruction-Group"].size(); j++) {
      uint16_t group = port_node["Instruction-Group"][j].as<uint16_t>();
      groupExecutionInfo_[group].latency = latency;
      groupExecutionInfo_[group].stallCycles = throughput;
      // Set zero inheritance distance for latency assignment as it's explicitly
      // defined
      inheritanceDistance[group] = 0;
      // Add inherited support for those appropriate groups
      std::queue<uint16_t> groups;
      groups.push(group);
      // Set a distance counter as 1 to represent 1 level of inheritance
      uint8_t distance = 1;
      while (groups.size()) {
        // Determine if there's any inheritance
        if (groupInheritance.find(groups.front()) != groupInheritance.end()) {
          std::vector<uint16_t> inheritedGroups =
              groupInheritance.at(groups.front());
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
    for (size_t j = 0; j < port_node["Instruction-Opcode"].size(); j++) {
      uint16_t opcode = port_node["Instruction-Opcode"][j].as<uint16_t>();
      opcodeExecutionInfo_[opcode].latency = latency;
      opcodeExecutionInfo_[opcode].stallCycles = throughput;
    }
  }

  // ports entries in the groupExecutionInfo_ entries only apply for models
  // using the outoforder core archetype
  if (config["Core"]["Simulation-Mode"].as<std::string>() == "outoforder") {
    // Create mapping between instructions groups and the ports that support
    // them
    for (size_t i = 0; i < config["Ports"].size(); i++) {
      // Store which ports support which groups
      YAML::Node group_node = config["Ports"][i]["Instruction-Group-Support"];
      for (size_t j = 0; j < group_node.size(); j++) {
        uint16_t group = group_node[j].as<uint16_t>();
        uint8_t newPort = static_cast<uint8_t>(i);
        groupExecutionInfo_[group].ports.push_back(newPort);
        // Add inherited support for those appropriate groups
        std::queue<uint16_t> groups;
        groups.push(group);
        while (groups.size()) {
          // Determine if there's any inheritance
          if (groupInheritance.find(groups.front()) != groupInheritance.end()) {
            std::vector<uint16_t> inheritedGroups =
                groupInheritance.at(groups.front());
            for (int k = 0; k < inheritedGroups.size(); k++) {
              groupExecutionInfo_[inheritedGroups[k]].ports.push_back(newPort);
              groups.push(inheritedGroups[k]);
            }
          }
          groups.pop();
        }
      }
      // Store any opcode-based port support override
      YAML::Node opcode_node = config["Ports"][i]["Instruction-Opcode-Support"];
      for (size_t j = 0; j < opcode_node.size(); j++) {
        // If latency information hasn't been defined, set to zero as to inform
        // later access to use group defined latencies instead
        uint16_t opcode = opcode_node[j].as<uint16_t>();
        opcodeExecutionInfo_.try_emplace(
            opcode, simeng::arch::aarch64::ExecutionInfo{0, 0, {}});
        opcodeExecutionInfo_[opcode].ports.push_back(static_cast<uint8_t>(i));
      }
    }
  }
}
Architecture::~Architecture() {
  cs_close(&capstoneHandle);
  decodeCache.clear();
  metadataCache.clear();
  groupExecutionInfo_.clear();
}

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                BranchPrediction prediction,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv8
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    uop->setBranchPrediction(prediction);
    // Return non-zero value to avoid fatal error
    return 1;
  }

  assert(bytesAvailable >= 4 &&
         "Fewer than 4 bytes supplied to AArch64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  // `ptr` is not guaranteed to be aligned.
  uint32_t insn;
  memcpy(&insn, ptr, 4);
  const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

  // Try to find the decoding in the decode cache
  auto iter = decodeCache.find(insn);
  if (iter == decodeCache.end()) {
    // No decoding present. Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

    bool success =
        cs_disasm_iter(capstoneHandle, &encoding, &size, &address, &rawInsn);

    auto metadata =
        success ? InstructionMetadata(rawInsn) : InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache.emplace_front(metadata);

    // Create and cache an instruction using the metadata
    iter = decodeCache.try_emplace(insn, *this, metadataCache.front()).first;

    // Set execution information for this instruction
    iter->second.setExecutionInfo(getExecutionInfo(iter->second));
    // std::cout << "### 0x" << std::hex << instructionAddress << std::dec
    //           << std::endl;
    // printMetadata(iter->second, capstoneHandle);
  }

  // Split instruction into 1 or more defined micro-ops
  // std::cout << "### 0x" << std::hex << instructionAddress << std::dec << "
  // ###"
  //           << std::endl;
  uint8_t num_ops = microDecoder_->decode(*this, iter->first, iter->second,
                                          output, capstoneHandle);

  // Set instruction address and branch prediction for each micro-op generated
  for (int i = 0; i < num_ops; i++) {
    output[i]->setInstructionAddress(instructionAddress);
    output[i]->setBranchPrediction(prediction);
  }

  return 4;
}

ExecutionInfo Architecture::getExecutionInfo(Instruction& insn) const {
  // Asusme no opcode-based override
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

std::shared_ptr<arch::ExceptionHandler> Architecture::handleException(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory) const {
  return std::make_shared<ExceptionHandler>(instruction, core, memory, linux_);
}

std::vector<RegisterFileStructure> Architecture::getRegisterFileStructures()
    const {
  uint16_t numSysRegs = static_cast<uint16_t>(systemRegisterMap_.size());
  return {
      {8, 32},          // General purpose
      {256, 32},        // Vector
      {32, 17},         // Predicate
      {1, 1},           // NZCV
      {8, numSysRegs},  // System
  };
}

uint16_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  // Check below is done for speculative instructions that may be passed into
  // the function but will not be executed. If such invalid speculative
  // instructions get through they can cause an out-of-range error.
  if (!systemRegisterMap_.count(reg)) return 0;
  return systemRegisterMap_.at(reg);
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
      {RegisterType::SYSTEM, getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0)});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(0b10100));

  return changes;
}

ProcessStateChange Architecture::getUpdateState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type
  changes.type = ChangeType::INCREMENT;

  // Increment the Counter-timer Virtual Count (CNTVCT) register by 1
  /* TODO: CNTVCT value should be equal to the physical count value minus
   * the virtual offset visible in CNTVOFF. */
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM, getSystemRegisterTag(ARM64_SYSREG_CNTVCT_EL0)});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(1));

  return changes;
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint64_t Architecture::getVectorLength() const { return VL_; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
