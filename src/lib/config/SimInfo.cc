#include "simeng/config/SimInfo.hh"

namespace simeng {
namespace config {

ryml::ConstNodeRef SimInfo::getConfig() {
  return getInstance()->validatedConfig_.crootref();
}

void SimInfo::setConfig(std::string path) { getInstance()->makeConfig(path); }

void SimInfo::addToConfig(std::string configAdditions) {
  getInstance()->modelConfig_.addConfigOptions(configAdditions);
  // Replace the validated config with new instance with the supplied
  // additional values
  getInstance()->validatedConfig_ = getInstance()->modelConfig_.getConfig();
  // Update previously extracted values from the config file
  getInstance()->extractValues();
}

void SimInfo::generateDefault(ISA isa, bool force) {
  if (isa == ISA::AArch64)
    getInstance()->modelConfig_.reGenerateDefault(ISA::AArch64, force);
  else if (isa == ISA::RV64)
    getInstance()->modelConfig_.reGenerateDefault(ISA::RV64, force);

  // Update config path to be the default string
  getInstance()->configFilePath_ = DEFAULT_STR;

  // Replace the validated config with the new default config
  getInstance()->validatedConfig_ = getInstance()->modelConfig_.getConfig();
  // Update previously extracted values from the config file
  getInstance()->extractValues();
}

std::string SimInfo::getConfigPath() { return getInstance()->configFilePath_; }

SimulationMode SimInfo::getSimMode() { return getInstance()->mode_; }

std::string SimInfo::getSimModeStr() { return getInstance()->modeStr_; }

ISA SimInfo::getISA() { return getInstance()->isa_; }

std::string SimInfo::getISAString() { return getInstance()->isaString_; }

const std::vector<simeng::RegisterFileStructure>& SimInfo::getArchRegStruct() {
  return getInstance()->archInfo_->getArchRegStruct();
}

const std::vector<simeng::RegisterFileStructure>& SimInfo::getPhysRegStruct() {
  return getInstance()->archInfo_->getPhysRegStruct();
}

const std::vector<uint16_t>& SimInfo::getPhysRegQuantities() {
  return getInstance()->archInfo_->getPhysRegQuantities();
}

const std::vector<uint64_t>& SimInfo::getSysRegVec() {
  return getInstance()->archInfo_->getSysRegEnums();
}

bool SimInfo::getGenSpecFiles() { return getInstance()->genSpecialFiles_; }

void SimInfo::reBuild() { getInstance()->extractValues(); }

SimInfo::SimInfo() {
  // Set the validated config file to be the current default config
  // generated by the default constructor of ModelConfig
  validatedConfig_ = modelConfig_.getConfig();
  extractValues();
}

std::unique_ptr<SimInfo>& SimInfo::getInstance() {
  static std::unique_ptr<SimInfo> SimInfoClass = nullptr;
  if (SimInfoClass == nullptr) {
    SimInfoClass = std::unique_ptr<SimInfo>(new SimInfo());
  }
  return SimInfoClass;
}

void SimInfo::makeConfig(std::string path) {
  // Recreate the model config instance from the YAML file path
  modelConfig_ = ModelConfig(path);

  // Update config path to be the passed path
  configFilePath_ = path;

  // Update the validated config file
  validatedConfig_ = modelConfig_.getConfig();
  extractValues();
}

void SimInfo::extractValues() {
  // Get ISA type and set the corresponding ArchInfo class
  isaString_ = validatedConfig_["Core"]["ISA"].as<std::string>();
  if (isaString_ == "AArch64") {
    isa_ = ISA::AArch64;
    archInfo_ = std::make_unique<arch::aarch64::ArchInfo>(
        arch::aarch64::ArchInfo(validatedConfig_));
  } else if (isaString_ == "rv64") {
    isa_ = ISA::RV64;
    archInfo_ = std::make_unique<arch::riscv::ArchInfo>(
        arch::riscv::ArchInfo(validatedConfig_));
  }

  // Get Simulation mode
  std::string mode =
      validatedConfig_["Core"]["Simulation-Mode"].as<std::string>();
  if (mode == "emulation") {
    mode_ = SimulationMode::Emulation;
    modeStr_ = "Emulation";
  } else if (mode == "inorderpipelined") {
    mode_ = SimulationMode::InOrderPipelined;
    modeStr_ = "In-Order Pipelined";
  } else if (mode == "outoforder") {
    mode_ = SimulationMode::Outoforder;
    modeStr_ = "Out-of-Order";
  }

  // Get if the special files directory should be created
  genSpecialFiles_ =
      validatedConfig_["CPU-Info"]["Generate-Special-Dir"].as<bool>();
}

}  // namespace config
}  // namespace simeng