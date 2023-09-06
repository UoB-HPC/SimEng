#include "simeng/arch/riscv/Architecture.hh"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <queue>
#include <string>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace riscv {

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;

Architecture::Architecture(kernel::Linux& kernel, YAML::Node config, std::shared_ptr<simeng::MemoryInterface>& dataMemory)
: 
  linux_(kernel)
{
  is32Bit_ = ARCH_64BIT;
  if (config["Core"]["ISA"].as<std::string>() == "rv32") {
    is32Bit_ = ARCH_32BIT;
  }

  cs_mode csMode = CS_MODE_RISCV64;
  constantsPool constantsPool;

  if(is32Bit_) {
    csMode = CS_MODE_RISCV32GC; // TODO Note: currently using local (1-line)modified capstone
    constants_.alignMask = constantsPool.alignMaskCompressed;
    constants_.regWidth = constantsPool.byteLength32;
    constants_.bytesLimit = constantsPool.bytesLimitCompressed;
  } else {
    constants_.alignMask = constantsPool.alignMask;
    constants_.regWidth = constantsPool.byteLength64;
    constants_.bytesLimit = constantsPool.bytesLimit;
  }
  cs_err n = cs_open(CS_ARCH_RISCV, csMode, &capstoneHandle);
  if (n != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle due "
                 "to error "
              << n << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
  systemRegisterMap_[SYSREG_MSTATUS] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MIE] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MTVEC] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MSTATUSH] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MSCRATCH] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MEPC] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MCAUSE] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MHARTID] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_MXCPTSC] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_CYCLE] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_TIME] = systemRegisterMap_.size();
  systemRegisterMap_[SYSREG_INSTRRET] = systemRegisterMap_.size();

  // Memory Mapped System Register Blocks

  // if elf file includes the label tohost then assume that this binary supports HTIF protocol (used by spike) and include an HTI block
  uint64_t htifAddress;
  if (linux_.lookupSymbolValue("tohost",htifAddress))
  {
    std::cout << "[SimEng] HTIF detected at: " << std::hex << htifAddress << std::endl;
    htif = std::make_shared<HostTargetInterface>(*this);
    memoryMappedSystemRegisterBlocks[htifAddress] = htif.get();
  }

  // Install CLINT into memort map, this is optional
  clint = std::make_shared<Clint>(*this);
  memoryMappedSystemRegisterBlocks[Clint::CLINT_BASE] = clint.get();

  if (!memoryMappedSystemRegisterBlocks.empty())
  {
    systemRegisterMemoryInterface = std::make_shared<SystemRegisterMemoryInterface>(dataMemory, memoryMappedSystemRegisterBlocks);
    dataMemory = systemRegisterMemoryInterface;
  }

  // Instantiate an executionInfo entry for each group in the InstructionGroup
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
            opcode, simeng::arch::riscv::executionInfo{0, 0, {}});
        opcodeExecutionInfo_[opcode].ports.push_back(static_cast<uint8_t>(i));
      }
    }
  }
  if (config["Core"]["Trace"].IsDefined() && config["Core"]["Trace"].as<bool>()) {
    traceFile_ = new std::ofstream();
    traceFile_->open("./trace.log");
    traceOn_ = true;
  }
}
Architecture::~Architecture() {
  cs_close(&capstoneHandle);
  decodeCache.clear();
  metadataCache.clear();
  groupExecutionInfo_.clear();
  if(traceOn_) {
    traceFile_->close();
  }
}

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                MacroOp& output) const {

  // Check that instruction address is 4-byte aligned as required by RISC-V
  // 2-byte when Compressed ISA is supported
  if (instructionAddress & constants_.alignMask) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    // Return non-zero value to avoid fatal error
    return 1;
  }

  assert(bytesAvailable >= constants_.bytesLimit &&
         "Fewer than bytes limit supplied to RISC-V decoder");

  // Dereference the instruction pointer to obtain the instruction word
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
    Instruction newInsn(*this, metadataCache.front());
    // Set execution information for this instruction
    newInsn.setExecutionInfo(getExecutionInfo(newInsn));
    // Set byte length in instruction
    newInsn.setArchRegWidth(constants_.regWidth);
    // Cache the instruction
    iter = decodeCache.insert({insn, newInsn}).first;
  }

  output.resize(1);
  auto& uop = output[0];

  // Retrieve the cached instruction
  auto newinsn = std::make_shared<Instruction>(iter->second);

  // write to output
  uop = newinsn;
  uop->setInstructionAddress(instructionAddress);

  return iter->second.getMetadata().lenBytes;
}

executionInfo Architecture::getExecutionInfo(Instruction& insn) const {
  // Assume no opcode-based override
  executionInfo exeInfo = groupExecutionInfo_.at(insn.getGroup());
  if (opcodeExecutionInfo_.find(insn.getMetadata().opcode) !=
      opcodeExecutionInfo_.end()) {
    // Replace with overrided values
    executionInfo overrideInfo =
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
      {constants_.regWidth, 32},          // General purpose
      {constants_.regWidth, 32},          // Floating Point
      {constants_.regWidth, numSysRegs},  // System
  };
}

int32_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  // Check below is done for speculative instructions that may be passed into
  // the function but will not be executed. If such invalid speculative
  // instructions get through they can cause an out-of-range error.
  if (systemRegisterMap_.count(reg))
    return systemRegisterMap_.at(reg);
  else
    return -1;
}

/** Returns a System Register index from a system register tag.
    reverse lookup slow but only used in printing so will be fine */
uint16_t Architecture::getSystemRegisterIdFromTag(int32_t tag) const {
  for (auto it = systemRegisterMap_.begin();it != systemRegisterMap_.end();it++)
      if (it->second == tag)
        return it->first;
  assert(0 && "Tag not found in systemRegisterMap");
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type
  changes.type = ChangeType::REPLACEMENT;
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 2});
  uint64_t stackPointer;
  // TODO: check if this conditional expression is needed
  if(is32Bit_) {
    stackPointer = (uint32_t)linux_.getInitialStackPointer();
    changes.modifiedRegisterValues.push_back((uint32_t)stackPointer);
  } else
  {
    stackPointer = linux_.getInitialStackPointer();
    changes.modifiedRegisterValues.push_back(stackPointer);
  }
  return changes;
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint8_t Architecture::getMinInstructionSize() const { return 2; }

std::vector<RegisterFileStructure>
Architecture::getConfigPhysicalRegisterStructure(YAML::Node config) const {
  return {{constants_.regWidth, config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>()},
          {constants_.regWidth, config["Register-Set"]["FloatingPoint-Count"].as<uint16_t>()},
          {constants_.regWidth, getNumSystemRegisters()}};
}

std::vector<uint16_t> Architecture::getConfigPhysicalRegisterQuantities(
    YAML::Node config) const {
  return {config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>(),
          config["Register-Set"]["FloatingPoint-Count"].as<uint16_t>(),
          getNumSystemRegisters()};
}
uint16_t Architecture::getNumSystemRegisters() const {
  return static_cast<uint16_t>(systemRegisterMap_.size());
}

int16_t Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  int16_t interruptId = -1;

  if (htif)
  {
    interruptId = htif->updateSystemTimerRegisters(regFile, iterations);
    if (interruptId>=0)
       return interruptId;
  }

  if (clint)
    interruptId = clint->updateSystemTimerRegisters(regFile, iterations);

  return interruptId;
}

void Architecture::updateInstrTrace(const std::shared_ptr<simeng::Instruction>& instruction,
                                    RegisterFileSet* regFile, uint64_t tick) const {
  if(traceOn_) {
    Instruction instr_ = *static_cast<Instruction*>(instruction.get());
    auto& metadata = instr_.getMetadata();
    std::stringstream s;
    s << "0x" << std::hex << instr_.getInstructionAddress() << " ";
    if (tick < 100000000)
      s << "t(" << std::setfill('0') << std::setw(8) << std::dec << (uint32_t)tick << ") ";
    else
      s << "t(" << std::setfill('0') << std::setw(16) << std::dec << (uint32_t)tick << ") ";
    s << "(";
    if(metadata.len == IL_16B) {
      s << "0000";
    }
    for(int8_t i=metadata.lenBytes; i>0; i--) {
      s << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned int>(metadata.encoding[i-1]);
    }
    s << ") ";
    s << metadata.mnemonic << " " << metadata.operandStr;
    auto sources = instr_.getOperandRegisters();
    auto destinations = instr_.getDestinationRegisters();
    int8_t num_src = (int8_t)sources.size();
    int8_t num_dest = (int8_t)destinations.size();
    if((num_src + num_dest) >0) {
      s << "    ";
      if (num_dest > 0) {
        s << "(d: ";
        for(int8_t i=0;i<num_dest; i++) {
          auto reg = destinations[i];
          if(reg.type == RegisterType::GENERAL) {
            s << "x" << std::dec << std::setfill('0') << std::setw(2) << reg.tag << "=0x";
          } else if(reg.type == RegisterType::FLOAT) {
            s << "f" << std::dec << std::setfill('0') << std::setw(2) << reg.tag << "=0x";
          } else if(reg.type == RegisterType::SYSTEM) {
            s << "csr_0x" << std::hex << std::setfill('0') << std::setw(3) << getSystemRegisterIdFromTag(reg.tag) << "=0x";
          }
          s << std::hex << std::setfill('0') << std::setw(8) << regFile->get(reg).get<uint32_t>();
          if(i < (num_dest-1)) {
            s << " ";
          }
        }
        s << ") ";
      }
      if (num_src > 0) {
        s << "(s: ";
        for(int8_t i=0;i<num_src; i++) {
          auto reg = sources[i];
          if(reg.type == RegisterType::GENERAL) {
            s << "x" << std::dec << std::setfill('0') << std::setw(2) << reg.tag << "=0x";
          } else if(reg.type == RegisterType::FLOAT) {
            s << "f" << std::dec << std::setfill('0') << std::setw(2) << reg.tag << "=0x";
          } else if(reg.type == RegisterType::SYSTEM) {
            s << "csr_0x" << std::hex << std::setfill('0') << std::setw(3) << getSystemRegisterIdFromTag(reg.tag) << "=0x";
          }
          s << std::hex << std::setfill('0') << std::setw(8) << regFile->get(reg).get<uint32_t>();
          if(i < (num_src-1)) {
            s << " ";
          }
        }
        s << ") ";
      }
    }
    s << std::endl;
    *traceFile_ << s.str();
    traceFile_->flush(); //Helps with debugging sometimes as all the state of previous committed instr is written to file.
  }
}
archConstants Architecture::getConstants() const { return constants_; }

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
