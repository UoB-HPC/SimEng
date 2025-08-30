#include "simeng/config/AcceleratorInfo.hh"

#include "simeng/arch/aarch64/ArchInfo.hh"
#include "simeng/arch/riscv/ArchInfo.hh"

namespace simeng {
namespace config {

AcceleratorInfo::AcceleratorInfo(const std::string& configPath)
    : modelConfig_(configPath, true), configFilePath_(configPath) {
  validatedConfig_ = modelConfig_.getConfig();

  // Get accelerator type
  type_ =
      parseAcceleratorType(validatedConfig_["Core"]["Type"].as<std::string>());

  // Get ISA type and set the corresponding ArchInfo class
  isaString_ = validatedConfig_["Core"]["ISA"].as<std::string>();
  if (isaString_ == "AArch64") {
    isa_ = ISA::AArch64;
    archInfo_ = std::make_unique<arch::aarch64::ArchInfo>(validatedConfig_);
  } else if (isaString_ == "rv64") {
    isa_ = ISA::RV64;
    archInfo_ = std::make_unique<arch::riscv::ArchInfo>(validatedConfig_);
  } else {
    assert(false && "Unknown ISA");
  }

  // Validate ISA against the type
  {
#define assert_isa(ISA_VARIANT) \
  assert(isa_ == ISA::ISA_VARIANT && "Invalid ISA - expected " #ISA_VARIANT)

    switch (type_) {
      case AcceleratorType::Undefined: {
        break;
      }
      case AcceleratorType::AArch64_SME: {
        assert_isa(AArch64);
        break;
      }
    }
  }

  // Get Simulation mode
  const auto mode =
      validatedConfig_["Core"]["Simulation-Mode"].as<std::string>();
  assert(mode == "outoforder" &&
         "Offloading is only supported when simulating an Out-of-Order core.");
  simMode_ = SimulationMode::Outoforder;
  simModeString_ = "Out-of-Order";
}

ryml::ConstNodeRef AcceleratorInfo::getConfig() const {
  return validatedConfig_.crootref();
}

const std::string& AcceleratorInfo::getConfigPath() const noexcept {
  return configFilePath_;
}

AcceleratorType AcceleratorInfo::getType() const noexcept { return type_; }

const char* AcceleratorInfo::getTypeString() const {
  return acceleratorTypeString(type_);
}

SimulationMode AcceleratorInfo::getSimMode() const noexcept { return simMode_; }

const std::string& AcceleratorInfo::getSimModeString() const {
  return simModeString_;
}

ISA AcceleratorInfo::getISA() const noexcept { return isa_; }

const std::string& AcceleratorInfo::getISAString() const { return isaString_; }

const std::vector<RegisterFileStructure>& AcceleratorInfo::getArchRegStruct()
    const {
  return archInfo_->getArchRegStruct();
}

const std::vector<RegisterFileStructure>& AcceleratorInfo::getPhysRegStruct()
    const {
  return archInfo_->getPhysRegStruct();
}

const std::vector<uint16_t>& AcceleratorInfo::getPhysRegQuantities() const {
  return archInfo_->getPhysRegQuantities();
}

const std::vector<uint64_t>& AcceleratorInfo::getSysRegVec() const {
  return archInfo_->getSysRegEnums();
}

}  // namespace config
}  // namespace simeng
