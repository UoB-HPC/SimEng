#include "simeng/arch/riscv/Architecture.hh"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <queue>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace riscv {

Architecture::Architecture(kernel::Linux& kernel, ryml::ConstNodeRef config)
    : arch::Architecture(kernel) {
  // Set initial rounding mode for F/D extensions
  // TODO set fcsr accordingly when Zicsr extension supported
  fesetround(FE_TONEAREST);

  cs_err n;

  // Check whether compressed instructions in use. Initialise variables and
  // Capstone accordingly
  if (config["Core"]["Compressed"].as<bool>()) {
    addressAlignmentMask_ = constantsPool::addressAlignMaskCompressed;
    minInsnLength_ = constantsPool::minInstWidthBytesCompressed;

    n = cs_open(CS_ARCH_RISCV,
                static_cast<cs_mode>(CS_MODE_RISCV64 | CS_MODE_RISCVC),
                &capstoneHandle_);
  } else {
    addressAlignmentMask_ = constantsPool::addressAlignMask;
    minInsnLength_ = constantsPool::minInstWidthBytes;

    n = cs_open(CS_ARCH_RISCV, static_cast<cs_mode>(CS_MODE_RISCV64),
                &capstoneHandle_);
  }

  if (n != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle due "
                 "to error "
              << n << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle_, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
  for (size_t i = 0; i < config::SimInfo::getSysRegVec().size(); i++) {
    systemRegisterMap_[config::SimInfo::getSysRegVec()[i]] =
        systemRegisterMap_.size();
  }

  cycleSystemReg_ = {
      RegisterType::SYSTEM,
      static_cast<uint16_t>(getSystemRegisterTag(RISCV_SYSREG_CYCLE))};

  // Instantiate an ExecutionInfo entry for each group in the InstructionGroup
  // namespace.
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
        // If latency information hasn't been defined, set to zero as to inform
        // later access to use group defined latencies instead
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
  // Check that instruction address is 4-byte aligned as required by RISC-V
  // 2-byte when Compressed extension is supported
  if (instructionAddress & addressAlignmentMask_) {
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

  assert(bytesAvailable >= minInsnLength_ &&
         "Fewer than bytes limit supplied to RISC-V decoder");

  // Get the first byte
  uint8_t firstByte = ((uint8_t*)ptr)[0];

  uint32_t insnEncoding = 0;
  size_t insnSize = 4;

  // Predecode bytes to determine whether we have a compressed instruction.
  // This will allow continuation if a compressed instruction is in the last 2
  // bytes of a fetch block, but will request more data if only half of a
  // non-compressed instruction is present

  // Check the 2 least significant bits as these determine instruction length
  if ((firstByte & 0b11) != 0b11) {
    // 2 byte - compressed
    // Only use relevant bytes
    // Dereference the instruction pointer to obtain the instruction word
    memcpy(&insnEncoding, ptr, 2);
    insnSize = 2;
  } else {
    // 4 byte
    if (bytesAvailable < 4) {
      // Not enough bytes available, bail
      return 0;
    }
    // Dereference the instruction pointer to obtain the instruction word
    memcpy(&insnEncoding, ptr, 4);
  }

  // Try to find the decoding in the decode cache
  auto iter = decodeCache_.find(insnEncoding);
  if (iter == decodeCache_.end()) {
    // No decoding present. Generate a fresh decoding, and add to cache
    // Calloc memory to ensure rawInsn is initialised with zeros. Errors can
    // occur otherwise as Capstone doesn't update variables for invalid
    // instructions
    cs_insn* rawInsnPointer = (cs_insn*)calloc(1, sizeof(cs_insn));
    cs_insn rawInsn = *rawInsnPointer;
    assert(rawInsn.size == 0 && "rawInsn not initialised correctly");

    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;
    // Size requires initialisation in case of capstone failure which won't
    // update this value
    rawInsn.size = insnSize;

    uint64_t address = 0;

    const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

    bool success = cs_disasm_iter(capstoneHandle_, &encoding, &insnSize,
                                  &address, &rawInsn);

    auto metadata = success ? InstructionMetadata(rawInsn)
                            : InstructionMetadata(encoding, rawInsn.size);

    free(rawInsnPointer);

    // Cache the metadata
    metadataCache_.push_front(metadata);

    // Create an instruction using the metadata
    Instruction newInsn(*this, metadataCache_.front());
    // Set execution information for this instruction
    newInsn.setExecutionInfo(getExecutionInfo(newInsn));

    // Cache the instruction
    iter = decodeCache_.insert({insnEncoding, newInsn}).first;
  }

  assert(((insnEncoding & 0b11) != 0b11
              ? iter->second.getMetadata().getInsnLength() == 2
              : iter->second.getMetadata().getInsnLength() == 4) &&
         "Predicted number of bytes don't match disassembled number of bytes");

  output.resize(1);
  auto& uop = output[0];

  // Retrieve the cached instruction and write to output
  uop = std::make_shared<Instruction>(iter->second);

  uop->setInstructionAddress(instructionAddress);

  return iter->second.getMetadata().getInsnLength();
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
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 2});
  changes.modifiedRegisterValues.push_back(stackPointer);

  return changes;
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint8_t Architecture::getMinInstructionSize() const { return minInsnLength_; }

void Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  regFile->set(cycleSystemReg_, iterations);
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

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
