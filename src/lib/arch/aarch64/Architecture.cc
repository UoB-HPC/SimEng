#include <algorithm>
#include <cassert>

#include "InstructionMetadata.hh"
#include "simeng/span.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

Architecture::Architecture(kernel::Linux& kernel,
                           const ryml::ConstNodeRef config)
    : Architecture(kernel, config, nullptr) {}

Architecture::Architecture(
    kernel::Linux& kernel,

    // This has to be passed by value because otherwise `getConfig` blows up
    // for some reason
    // ReSharper disable once CppPassValueParameterByConstReference
    // NOLINTBEGIN(*-unnecessary-value-param)
    std::shared_ptr<config::AcceleratorInfo> acceleratorInfo
    // NOLINTEND(*-unnecessary-value-param)

    )
    : Architecture(kernel, acceleratorInfo->getConfig(), acceleratorInfo) {}

Architecture::Architecture(
    kernel::Linux& kernel, const ryml::ConstNodeRef config,
    std::shared_ptr<config::AcceleratorInfo> acceleratorInfo)
    : arch::Architecture(kernel),
      microDecoder_(std::make_unique<MicroDecoder>()),
      VL_(config["Core"]["Vector-Length"].as<uint64_t>()),
      SVL_(config["Core"]["Streaming-Vector-Length"].as<uint64_t>()),
      vctModulo_(config["Core"]["Clock-Frequency-GHz"].as<float>() * 1e9 /
                 (config["Core"]["Timer-Frequency-MHz"].as<uint32_t>() * 1e6)),
      acceleratorInfo_(std::move(acceleratorInfo)) {
  if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &capstoneHandle_) != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle"
              << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle_, CS_OPT_DETAIL, CS_OPT_ON);
  // This second Capstone option reverses instruction aliases, and instead
  // means all operand information is that of the "real" underlying instruction.
  cs_option(capstoneHandle_, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);

  // Generate zero-indexed system register map
  const auto& sysRegs = acceleratorInfo_ == nullptr
                            ? config::SimInfo::getSysRegVec()
                            : acceleratorInfo_->getSysRegVec();
  for (const auto sysReg : sysRegs) {
    systemRegisterMap_[sysReg] = systemRegisterMap_.size();
  }

  // Get Virtual Counter Timer and Processor Cycle Counter system registers.
  VCTreg_ = {RegisterType::SYSTEM,
             static_cast<uint16_t>(Architecture::getSystemRegisterTag(
                 AARCH64_SYSREG_CNTVCT_EL0))};
  PCCreg_ = {RegisterType::SYSTEM,
             static_cast<uint16_t>(Architecture::getSystemRegisterTag(
                 AARCH64_SYSREG_PMCCNTR_EL0))};

  // Instantiate an ExecutionInfo entry for each group in the
  // InstructionGroup namespace.
  for (int i = 0; i < NUM_GROUPS; i++) {
    groupExecutionInfo_[i] = {1, 1, {}};
  }
  // Extract execution latency/throughput for each group
  std::vector<uint8_t> inheritanceDistance(NUM_GROUPS, UINT8_MAX);
  for (size_t i = 0; i < config["Latencies"].num_children(); i++) {
    ryml::ConstNodeRef port_node = config["Latencies"][i];
    const auto latency = port_node["Execution-Latency"].as<uint16_t>();
    const auto throughput = port_node["Execution-Throughput"].as<uint16_t>();
    for (size_t j = 0; j < port_node["Instruction-Group-Nums"].num_children();
         j++) {
      const auto group = port_node["Instruction-Group-Nums"][j].as<uint16_t>();
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
      while (!groups.empty()) {
        // Determine if there's any inheritance
        if (groupInheritance_.find(groups.front()) != groupInheritance_.end()) {
          const auto& inheritedGroups = groupInheritance_.at(groups.front());
          for (const auto inheritedGroup : inheritedGroups) {
            // Determine if this group has inherited latency values from a
            // smaller distance
            if (inheritanceDistance[inheritedGroup] > distance) {
              groupExecutionInfo_[inheritedGroup].latency = latency;
              groupExecutionInfo_[inheritedGroup].stallCycles = throughput;
              inheritanceDistance[inheritedGroup] = distance;
            }
            groups.push(inheritedGroup);
          }
        }
        groups.pop();
        distance++;
      }
    }
    // Store any opcode-based latency override
    for (size_t j = 0; j < port_node["Instruction-Opcodes"].num_children();
         j++) {
      const auto opcode = port_node["Instruction-Opcodes"][j].as<uint16_t>();
      opcodeExecutionInfo_[opcode].latency = latency;
      opcodeExecutionInfo_[opcode].stallCycles = throughput;
    }
  }

  // ports entries in the groupExecutionInfo_ entries only apply for models
  // using the outoforder core archetype
  const auto simMode = acceleratorInfo_ == nullptr
                           ? config::SimInfo::getSimMode()
                           : acceleratorInfo_->getSimMode();
  if (simMode == config::SimulationMode::Outoforder) {
    // Create mapping between instructions groups and the ports that support
    // them
    for (size_t i = 0; i < config["Ports"].num_children(); i++) {
      // Store which ports support which groups
      ryml::ConstNodeRef group_node =
          config["Ports"][i]["Instruction-Group-Support-Nums"];
      for (size_t j = 0; j < group_node.num_children(); j++) {
        const auto group = group_node[j].as<uint16_t>();
        const auto newPort = static_cast<uint16_t>(i);
        groupExecutionInfo_[group].ports.push_back(newPort);
        // Add inherited support for those appropriate groups
        std::queue<uint16_t> groups;
        groups.push(group);
        while (!groups.empty()) {
          // Determine if there's any inheritance
          if (groupInheritance_.find(groups.front()) !=
              groupInheritance_.end()) {
            const auto& inheritedGroups = groupInheritance_.at(groups.front());
            for (const auto inheritedGroup : inheritedGroups) {
              groupExecutionInfo_[inheritedGroup].ports.push_back(newPort);
              groups.push(inheritedGroup);
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
        const auto opcode = opcode_node[j].as<uint16_t>();
        opcodeExecutionInfo_.try_emplace(opcode, ExecutionInfo{0, 0, {}});
        opcodeExecutionInfo_[opcode].ports.push_back(static_cast<uint8_t>(i));
      }
    }
  }
}

Architecture::~Architecture() { cs_close(&capstoneHandle_); }

std::unique_ptr<simeng::Instruction> Architecture::deserializeFrom(
span<uint8_t>& buffer) const {
  // auto insn = std::make_unique<Instruction>(*this, buffer);
  // insn->setExecutionInfo(getExecutionInfo(*insn));

  // TODO: Get rid of this once deserialization starts working
  Instruction* insn_ptr = nullptr;
  deserialize_field(buffer, insn_ptr);
  auto insn = std::unique_ptr<simeng::Instruction>(insn_ptr);
  insn->setExecutionInfo(
      getExecutionInfo(*static_cast<Instruction*>(insn.get())));

  return insn;
}

uint8_t Architecture::predecode(const uint8_t* ptr, uint16_t bytesAvailable,
                                uint64_t instructionAddress,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv9.2-a
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = std::make_shared<InstructionMetadata>(ptr, 1);
    metadataCache_.push_front(std::move(metadata));
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

    const auto* encoding = ptr;

    bool success =
        cs_disasm_iter(capstoneHandle_, &encoding, &size, &address, &rawInsn);

    auto metadata = success ? std::make_shared<InstructionMetadata>(rawInsn)
                            : std::make_shared<InstructionMetadata>(encoding);

    // Cache the metadata
    metadataCache_.push_front(std::move(metadata));

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

int32_t Architecture::getSystemRegisterTag(const uint16_t reg) const {
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
  changes.modifiedRegisterValues.emplace_back(stackPointer);

  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM,
       static_cast<uint16_t>(getSystemRegisterTag(AARCH64_SYSREG_DCZID_EL0))});
  changes.modifiedRegisterValues.emplace_back(static_cast<uint64_t>(0b10100));

  return changes;
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint8_t Architecture::getMinInstructionSize() const { return 4; }

void Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  // Update the Processor Cycle Counter to total cycles completed.
  regFile->set(PCCreg_, iterations);
  // Update Virtual Counter Timer at correct frequency.
  if (iterations % static_cast<uint64_t>(vctModulo_) == 0) {
    regFile->set(VCTreg_, regFile->get(VCTreg_).get<uint64_t>() + 1);
  }
}

ExecutionInfo Architecture::getExecutionInfo(const Instruction& insn) const {
  // Assume no opcode-based override
  ExecutionInfo exeInfo = groupExecutionInfo_.at(insn.getGroup());
  if (opcodeExecutionInfo_.find(insn.getMetadata().opcode) !=
      opcodeExecutionInfo_.end()) {
    // Replace with overridden values
    const auto& [latency, stallCycles, ports] =
        opcodeExecutionInfo_.at(insn.getMetadata().opcode);
    if (latency != 0) exeInfo.latency = latency;
    if (stallCycles != 0) exeInfo.stallCycles = stallCycles;
    if (!ports.empty()) exeInfo.ports = ports;
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

// 0th bit of SVCR register determines if streaming-mode is enabled.
bool Architecture::isStreamingModeEnabled() const { return SVCRval_ & 1; }

// 1st bit of SVCR register determines if ZA register is enabled.
bool Architecture::isZARegisterEnabled() const { return SVCRval_ & 2; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
