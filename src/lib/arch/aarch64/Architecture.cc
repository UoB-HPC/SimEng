#include <algorithm>
#include <cassert>

#include "InstructionMetadata.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;

Architecture::Architecture() : microDecoder_(std::make_unique<MicroDecoder>()) {
  std::ostringstream str;
  str << SIMENG_SOURCE_DIR << "/simengMetadata.out";
  outputFile_.open(str.str(), std::ofstream::out);
  outputFile_.close();
  outputFile_.open(str.str(), std::ofstream::out | std::ofstream::app);

  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle"
              << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Initialise SVE and SME vector lengths
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  config["Core"]["Vector-Length"] >> VL_;
  config["Core"]["Streaming-Vector-Length"] >> SVL_;
  // Initialise virtual counter timer increment frequency
  vctModulo_ =
      (config::SimInfo::getValue<float>(config["Core"]["Clock-Frequency"]) *
       1e9) /
      (config::SimInfo::getValue<uint32_t>(config["Core"]["Timer-Frequency"]) *
       1e6);

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

  // Instantiate an ExecutionInfo entry for each group in the InstructionGroup
  // namespace.
  for (int i = 0; i < NUM_GROUPS; i++) {
    groupExecutionInfo_[i] = {1, 1, {}};
  }
  // Extract execution latency/throughput for each group
  std::vector<uint8_t> inheritanceDistance(NUM_GROUPS, UINT8_MAX);
  for (size_t i = 0; i < config["Latencies"].num_children(); i++) {
    ryml::ConstNodeRef port_node = config["Latencies"][i];
    uint16_t latency;
    port_node["Execution-Latency"] >> latency;
    uint16_t throughput;
    port_node["Execution-Throughput"] >> throughput;
    for (size_t j = 0; j < port_node["Instruction-Group-Nums"].num_children();
         j++) {
      uint16_t group;
      port_node["Instruction-Group-Nums"][j] >> group;
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
    for (size_t j = 0; j < port_node["Instruction-Opcodes"].num_children();
         j++) {
      uint16_t opcode;
      port_node["Instruction-Opcodes"][j] >> opcode;
      opcodeExecutionInfo_[opcode].latency = latency;
      opcodeExecutionInfo_[opcode].stallCycles = throughput;
    }
  }

  // Ports entries in the groupExecutionInfo_ entries only apply for
  // non-emulation core archetypes
  if (config::SimInfo::getSimMode() != config::simMode::emulation) {
    // Create mapping between instructions groups and the ports that support
    // them
    for (size_t i = 0; i < config["Ports"].num_children(); i++) {
      // Store which ports support which groups
      ryml::ConstNodeRef group_node =
          config["Ports"][i]["Instruction-Group-Support-Nums"];
      for (size_t j = 0; j < group_node.num_children(); j++) {
        uint16_t group;
        group_node[j] >> group;
        uint16_t newPort = static_cast<uint16_t>(i);
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
      ryml::ConstNodeRef opcode_node =
          config["Ports"][i]["Instruction-Opcode-Support"];
      for (size_t j = 0; j < opcode_node.num_children(); j++) {
        // If latency information hasn't been defined, set to zero as to inform
        // later access to use group defined latencies instead
        uint16_t opcode;
        opcode_node[j] >> opcode;
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
  outputFile_.close();
}

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv9.2-a
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    uop->setSequenceId(instrSeqIdCtr_++);
    uop->setInstructionId(insnIdCtr_++);
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
    metadataCache.push_front(metadata);

    // Create an instruction using the metadata
    Instruction newInsn(*this, metadataCache.front(), MicroOpInfo());
    // Set execution information for this instruction
    newInsn.setExecutionInfo(getExecutionInfo(newInsn));
    // Cache the instruction
    iter = decodeCache.insert({insn, newInsn}).first;

    if (instructionAddress < 0) {
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
      outputFile_ << "\taddress = " << rawInsn.address << std::endl;
      outputFile_ << "\tsize = " << rawInsn.size << std::endl;
      outputFile_ << "Other InstructionMetadata details:" << std::endl;
      outputFile_ << "\tgroupCount = " << unsigned(metadata.groupCount)
                  << std::endl;
      outputFile_ << "Operands:" << std::endl;
      if ((&rawInsn)->detail != NULL) {
        if (metadata.operandCount)
          outputFile_ << "\top_count: " << unsigned(metadata.operandCount)
                      << std::endl;

        for (i = 0; i < metadata.operandCount; i++) {
          cs_arm64_op op = metadata.operands[i];
          switch (op.type) {
            default:
              break;
            case ARM64_OP_REG:
              outputFile_ << "\t\toperands[" << i << "].type: REG = "
                          << cs_reg_name(capstoneHandle, op.reg) << std::endl;
              break;
            case ARM64_OP_IMM:
              outputFile_ << "\t\toperands[" << i << "].type: IMM = 0x%"
                          << std::hex << op.imm << std::dec << std::endl;
              break;
            case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
              // Issue #681: Windows kernel does not support formatting float
              // point
              outputFile_ << "\t\toperands[" << i
                          << "].type: FP = <float_point_unsupported>"
                          << std::endl;
#else
              outputFile_ << "\t\toperands[" << i << "].type: FP = " << op.fp
                          << std::endl;
#endif
              break;
            case ARM64_OP_MEM:
              outputFile_ << "\t\toperands[" << i << "].type: MEM" << std::endl;
              if (op.mem.base != ARM64_REG_INVALID)
                outputFile_ << "\t\t\toperands[" << i << "].mem.base: REG = "
                            << cs_reg_name(capstoneHandle, op.mem.base)
                            << std::endl;
              if (op.mem.index != ARM64_REG_INVALID)
                outputFile_ << "\t\t\toperands[" << i << "].mem.index: REG = "
                            << cs_reg_name(capstoneHandle, op.mem.index)
                            << std::endl;
              if (op.mem.disp != 0)
                outputFile_ << "\t\t\toperands[" << i << "].mem.disp: 0x"
                            << std::hex << op.mem.disp << std::dec << std::endl;

              break;
            case ARM64_OP_CIMM:
              outputFile_ << "\t\toperands[" << i
                          << "].type: C-IMM = " << (int)op.imm << std::endl;
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
              outputFile_ << "\t\toperands[" << i << "].type: PSTATE = 0x"
                          << std::hex << op.pstate << std::dec << std::endl;
              break;
            case ARM64_OP_SYS:
              outputFile_ << "\t\toperands[" << i << "].type: SYS = 0x"
                          << std::hex << op.sys << std::dec << std::endl;
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
              outputFile_ << "\t\toperands[" << i << "].type: SYS = 0x"
                          << std::hex << op.sys << std::endl;
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
                            << std::hex << op.sme_index.disp << std::dec
                            << std::endl;
              break;
          }

          access = op.access;
          switch (access) {
            default:
              break;
            case CS_AC_READ:
              outputFile_ << "\t\toperands[" << i << "].access: READ"
                          << std::endl;
              break;
            case CS_AC_WRITE:
              outputFile_ << "\t\toperands[" << i << "].access: WRITE"
                          << std::endl;
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
            outputFile_ << "\t\t\tVector Index: " << op.vector_index
                        << std::endl;
        }

        if (metadata.setsFlags)
          outputFile_ << "\tUpdate-flags: True" << std::endl;

        if (metadata.writeback)
          outputFile_ << "\tWrite-back: True" << std::endl;

        if (metadata.cc)
          outputFile_ << "\tCode-condition: " << unsigned(metadata.cc)
                      << std::endl;

        // Print out all registers read by this instruction
        outputFile_ << "\tRegisters read:";
        for (i = 0; i < metadata.implicitSourceCount; i++) {
          outputFile_ << " "
                      << cs_reg_name(capstoneHandle,
                                     metadata.implicitSources[i]);
        }
        for (i = 0; i < metadata.operandCount; i++) {
          if (metadata.operands[i].type == ARM64_OP_REG &&
              metadata.operands[i].access & CS_AC_READ)
            outputFile_ << " "
                        << cs_reg_name(capstoneHandle,
                                       metadata.operands[i].reg);
        }
        outputFile_ << std::endl;
        // Print out all registers written to this instruction
        outputFile_ << std::endl;
        // Print out all registers written to this instruction
        outputFile_ << "\tRegisters modified:";
        for (i = 0; i < metadata.implicitDestinationCount; i++) {
          outputFile_ << " "
                      << cs_reg_name(capstoneHandle,
                                     metadata.implicitDestinations[i])
                      << std::endl;
        }
        for (i = 0; i < metadata.operandCount; i++) {
          if (metadata.operands[i].type == ARM64_OP_REG &&
              metadata.operands[i].access & CS_AC_WRITE)
            outputFile_ << " "
                        << cs_reg_name(capstoneHandle,
                                       metadata.operands[i].reg);
        }
        outputFile_ << std::endl;
      }
    }
  }

  // Split instruction into 1 or more defined micro-ops
  uint8_t num_ops = microDecoder_->decode(*this, iter->first, iter->second,
                                          output, capstoneHandle);

  // Set instruction address and branch prediction for each micro-op generated
  for (int i = 0; i < num_ops; i++) {
    output[i]->setSequenceId(instrSeqIdCtr_++);
    output[i]->setInstructionId(insnIdCtr_);
    output[i]->setInstructionAddress(instructionAddress);
  }
  // Increment insnIdCtr_
  insnIdCtr_++;
  // decodeCache.erase(iter);

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

int32_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  // Check below is done for speculative instructions that may be passed into
  // the function but will not be executed. If such invalid speculative
  // instructions get through they can cause an out-of-range error.
  if (!systemRegisterMap_.count(reg)) return -1;
  return systemRegisterMap_.at(reg);
}

uint16_t Architecture::getNumSystemRegisters() const {
  return static_cast<uint16_t>(systemRegisterMap_.size());
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint64_t Architecture::getVectorLength() const { return VL_; }

uint64_t Architecture::getStreamingVectorLength() const { return SVL_; }

void Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  // Update the Processor Cycle Counter to total cycles completed.
  regFile->set(PCCreg_, iterations);
  // Update Virtual Counter Timer at correct frequency.
  if (iterations % (uint64_t)vctModulo_ == 0) {
    regFile->set(VCTreg_, regFile->get(VCTreg_).get<uint64_t>() + 1);
  }
}

std::vector<RegisterFileStructure>
Architecture::getConfigPhysicalRegisterStructure() const {
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  // Matrix-Count multiplied by (SVL/8) as internal representation of
  // ZA is a block of row-vector-registers. Therefore we need to
  // convert physical counts from whole-ZA to rows-in-ZA.
  uint16_t matCount = config::SimInfo::getValue<uint16_t>(
                          config["Register-Set"]["Matrix-Count"]) *
                      (config::SimInfo::getValue<uint16_t>(
                           config["Core"]["Streaming-Vector-Length"]) /
                       8);
  return {{8, config::SimInfo::getValue<uint16_t>(
                  config["Register-Set"]["GeneralPurpose-Count"])},
          {256, config::SimInfo::getValue<uint16_t>(
                    config["Register-Set"]["FloatingPoint/SVE-Count"])},
          {32, config::SimInfo::getValue<uint16_t>(
                   config["Register-Set"]["Predicate-Count"])},
          {1, config::SimInfo::getValue<uint16_t>(
                  config["Register-Set"]["Conditional-Count"])},
          {8, getNumSystemRegisters()},
          {256, matCount}};
}

std::vector<uint16_t> Architecture::getConfigPhysicalRegisterQuantities()
    const {
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  // Matrix-Count multiplied by (SVL/8) as internal representation of
  // ZA is a block of row-vector-registers. Therefore we need to convert
  // physical counts from whole-ZA to rows-in-ZA.
  uint16_t matCount = config::SimInfo::getValue<uint16_t>(
                          config["Register-Set"]["Matrix-Count"]) *
                      (config::SimInfo::getValue<uint16_t>(
                           config["Core"]["Streaming-Vector-Length"]) /
                       8);
  return {config::SimInfo::getValue<uint16_t>(
              config["Register-Set"]["GeneralPurpose-Count"]),
          config::SimInfo::getValue<uint16_t>(
              config["Register-Set"]["FloatingPoint/SVE-Count"]),
          config::SimInfo::getValue<uint16_t>(
              config["Register-Set"]["Predicate-Count"]),
          config::SimInfo::getValue<uint16_t>(
              config["Register-Set"]["Conditional-Count"]),
          getNumSystemRegisters(),
          matCount};
}

/** The SVCR value is stored in Architecture to allow the value to be
 * retrieved within execution pipeline. This prevents adding an implicit
 * operand to every SME instruction; reducing the amount of complexity when
 * implementing SME execution logic. */
uint64_t Architecture::getSVCRval() const { return SVCRval_; }

void Architecture::setSVCRval(const uint64_t newVal) const {
  // As SVCRval_ is mutable, we can change its value in a const function
  SVCRval_ = newVal;
}

void Architecture::updateAfterContextSwitch(
    const simeng::OS::cpuContext& context) const {
  // As SVCRval_ is mutable, we can change its value in a const function
  SVCRval_ = context
                 .regFile[RegisterType::SYSTEM]
                         [getSystemRegisterTag(ARM64_SYSREG_SVCR)]
                 .get<uint64_t>();
}

void Architecture::printMetadata(const void* ptr, uint64_t insn_address,
                                 int pid) const {
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

  int i;
  uint8_t access;
  std::cout << "[SimEng:ExceptionHandler:" << pid
            << "]       Metadata:" << std::endl;
  if (metadata.operandCount)
    std::cout << "[SimEng:ExceptionHandler:" << pid
              << "]       \top_count: " << unsigned(metadata.operandCount)
              << std::endl;

  for (i = 0; i < metadata.operandCount; i++) {
    cs_arm64_op op = metadata.operands[i];
    switch (op.type) {
      default:
        break;
      case ARM64_OP_REG:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i
                  << "].type: REG = " << cs_reg_name(capstoneHandle, op.reg)
                  << std::endl;
        break;
      case ARM64_OP_IMM:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: IMM = 0x%"
                  << std::hex << op.imm << std::dec << std::endl;
        break;
      case ARM64_OP_FP:
#if defined(_KERNEL_MODE)
        // Issue #681: Windows kernel does not support formatting float
        // point
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i
                  << "].type: FP = <float_point_unsupported>" << std::endl;
#else
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: FP = " << op.fp
                  << std::endl;
#endif
        break;
      case ARM64_OP_MEM:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: MEM" << std::endl;
        if (op.mem.base != ARM64_REG_INVALID)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].mem.base: REG = "
                    << cs_reg_name(capstoneHandle, op.mem.base) << std::endl;
        if (op.mem.index != ARM64_REG_INVALID)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].mem.index: REG = "
                    << cs_reg_name(capstoneHandle, op.mem.index) << std::endl;
        if (op.mem.disp != 0)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].mem.disp: 0x"
                    << std::hex << op.mem.disp << std::dec << std::endl;

        break;
      case ARM64_OP_CIMM:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i
                  << "].type: C-IMM = " << (int)op.imm << std::endl;
        break;
      case ARM64_OP_REG_MRS:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: REG_MRS = 0x"
                  << std::hex << op.reg << std::dec << std::endl;
        break;
      case ARM64_OP_REG_MSR:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: REG_MSR = 0x"
                  << std::hex << op.reg << std::dec << std::endl;
        break;
      case ARM64_OP_PSTATE:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: PSTATE = 0x"
                  << std::hex << op.pstate << std::dec << std::endl;
        break;
      case ARM64_OP_SYS:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: SYS = 0x"
                  << std::hex << op.sys << std::dec << std::endl;
        break;
      case ARM64_OP_PREFETCH:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: PREFETCH = 0x"
                  << std::hex << op.prefetch << std::dec << std::endl;
        break;
      case ARM64_OP_BARRIER:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: BARRIER = 0x"
                  << std::hex << op.barrier << std::dec << std::endl;
        break;
      case ARM64_OP_SVCR:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: SYS = 0x"
                  << std::hex << op.sys << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRSM)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].svcr: BIT = SM"
                    << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRZA)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].svcr: BIT = ZA"
                    << std::endl;
        if (op.svcr == ARM64_SVCR_SVCRSMZA)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].svcr: BIT = SM & ZA"
                    << std::endl;
        break;
      case ARM64_OP_SME_INDEX:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].type: REG = "
                  << cs_reg_name(capstoneHandle, op.sme_index.reg) << std::endl;
        if (op.sme_index.base != ARM64_REG_INVALID)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].index.base: REG = "
                    << cs_reg_name(capstoneHandle, op.sme_index.base)
                    << std::endl;
        if (op.sme_index.disp != 0)
          std::cout << "[SimEng:ExceptionHandler:" << pid
                    << "]       \t\t\toperands[" << i << "].index.disp: 0x"
                    << std::hex << op.sme_index.disp << std::dec << std::endl;
        break;
    }

    access = op.access;
    switch (access) {
      default:
        break;
      case CS_AC_READ:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].access: READ"
                  << std::endl;
        break;
      case CS_AC_WRITE:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].access: WRITE"
                  << std::endl;
        break;
      case CS_AC_READ | CS_AC_WRITE:
        std::cout << "[SimEng:ExceptionHandler:" << pid
                  << "]       \t\toperands[" << i << "].access: READ | WRITE"
                  << std::endl;
        break;
    }

    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value)
      std::cout << "[SimEng:ExceptionHandler:" << pid
                << "]       \t\t\tShift: type = " << op.shift.type
                << ", value = " << op.shift.value << std::endl;

    if (op.ext != ARM64_EXT_INVALID)
      std::cout << "[SimEng:ExceptionHandler:" << pid
                << "]       \t\t\tExt: " << op.ext << std::endl;

    if (op.vas != ARM64_VAS_INVALID)
      std::cout << "[SimEng:ExceptionHandler:" << pid
                << "]       \t\t\tVector Arrangement Specifier: 0x" << std::hex
                << op.vas << std::dec << std::endl;

    if (op.vector_index != -1)
      std::cout << "[SimEng:ExceptionHandler:" << pid
                << "]       \t\t\tVector Index: " << op.vector_index
                << std::endl;
  }

  if (metadata.setsFlags)
    std::cout << "[SimEng:ExceptionHandler:" << pid
              << "]       \tUpdate-flags: True" << std::endl;

  if (metadata.writeback)
    std::cout << "[SimEng:ExceptionHandler:" << pid
              << "]       \tWrite-back: True" << std::endl;

  if (metadata.cc)
    std::cout << "[SimEng:ExceptionHandler:" << pid
              << "]       \tCode-condition: " << unsigned(metadata.cc)
              << std::endl;

  // Print out all registers read by this instruction
  std::cout << "[SimEng:ExceptionHandler:" << pid
            << "]       \tRegisters read:";
  for (i = 0; i < metadata.implicitSourceCount; i++) {
    std::cout << " "
              << cs_reg_name(capstoneHandle, metadata.implicitSources[i]);
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access & CS_AC_READ)
      std::cout << " " << cs_reg_name(capstoneHandle, metadata.operands[i].reg);
  }
  std::cout << std::endl;
  // Print out all registers written to this instruction
  std::cout << "[SimEng:ExceptionHandler:" << pid
            << "]       \tRegisters modified:";
  for (i = 0; i < metadata.implicitDestinationCount; i++) {
    std::cout << " "
              << cs_reg_name(capstoneHandle, metadata.implicitDestinations[i]);
  }
  for (i = 0; i < metadata.operandCount; i++) {
    if (metadata.operands[i].type == ARM64_OP_REG &&
        metadata.operands[i].access & CS_AC_WRITE)
      std::cout << " " << cs_reg_name(capstoneHandle, metadata.operands[i].reg);
  }
  std::cout << std::endl;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
