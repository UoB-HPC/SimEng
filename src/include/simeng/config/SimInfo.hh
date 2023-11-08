#pragma once

#include <iostream>
#include <string>

#include "simeng/Instruction.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/ArchInfo.hh"
#include "simeng/arch/riscv/ArchInfo.hh"
#include "simeng/config/ModelConfig.hh"
#include "simeng/config/yaml/ryml.hh"

#define DEFAULT_STR "Default"

namespace simeng {
namespace config {

/** Enum representing the possible simulation modes. */
enum class SimulationMode { Emulation, InOrderPipelined, Outoforder };

/** A SimInfo class to hold values, specified by the constructed ryml::Tree
 * object in the ModelConfig class and manually, used after the instantiation of
 * the current simulation and its objects. */
class SimInfo {
 public:
  /** A getter function to retrieve the ryml::Tree representing the underlying
   * model config file. */
  static ryml::ConstNodeRef getConfig() {
    return getInstance()->validatedConfig_.crootref();
  }

  /** A setter function to set the model config file from a path to a YAML file.
   */
  static void setConfig(std::string path) { getInstance()->makeConfig(path); }

  /** A function to add additional config values to the model config file. */
  static void addToConfig(std::string configAdditions) {
    getInstance()->modelConfig_.addConfigOptions(configAdditions);
    // Replace the validated config with new instance with the supplied
    // additional values
    getInstance()->validatedConfig_ = getInstance()->modelConfig_.getConfig();
    // Update previously extracted values from the config file
    getInstance()->extractValues();
  }

  /** A function to generate a default config file based on a passed ISA. */
  static void generateDefault(ISA isa, bool force = false) {
    if (isa == ISA::AArch64)
      getInstance()->modelConfig_.reGenerateDefault(ISA::AArch64, force);
    else if (isa == ISA::RV64)
      getInstance()->modelConfig_.reGenerateDefault(ISA::RV64, force);

    // Update config path to be the default string
    getInstance()->setConfigPath(DEFAULT_STR);

    // Replace the validated config with the new default config
    getInstance()->validatedConfig_ = getInstance()->modelConfig_.getConfig();
    // Update previously extracted values from the config file
    getInstance()->extractValues();
  }

  /** A utility function to get a value, of a specified type, from a config
   * option. */
  template <typename T>
  static T getValue(ryml::ConstNodeRef node) {
    T val;
    node >> val;
    return val;
  }

  /** A getter function to retrieve the config file path. */
  static std::string getConfigPath() { return getInstance()->configFilePath_; }

  /** A setter function to set the config file path. */
  static void setConfigPath(std::string path) {
    getInstance()->configFilePath_ = path;
  }

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance. */
  static SimulationMode getSimMode() { return getInstance()->mode_; }

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance as a string. */
  static std::string getSimModeStr() { return getInstance()->modeStr_; }

  /** A getter function to retrieve which ISA the current simulation is using.
   */
  static ISA getISA() { return getInstance()->isa_; }

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available architectural registers. */
  static const std::vector<simeng::RegisterFileStructure>& getArchRegStruct() {
    return getInstance()->archInfo_->getArchRegStruct();
  }

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available physical registers. */
  static const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct() {
    return getInstance()->archInfo_->getPhysRegStruct();
  }

  /** A getter function to retrieve a vector of uint16_t values describing
   * the quantities of physical registers available. */
  static const std::vector<uint16_t>& getPhysRegQuantities() {
    return getInstance()->archInfo_->getPhysRegQuantities();
  }

  /** A getter function to retrieve a vector of Capstone sysreg enums for
   * all the system registers that should be utilised in simulation. */
  static const std::vector<uint64_t>& getSysRegVec() {
    return getInstance()->archInfo_->getSysRegEnums();
  }

  /** A getter function to retrieve an index of a Capstone sysreg enum
   * within the sysRegisterEnums_ vector. */
  static uint32_t getSysRegVecIndex(uint64_t sysReg) {
    auto sysRegVec = getInstance()->archInfo_->getSysRegEnums();
    auto regItr = std::find(sysRegVec.begin(), sysRegVec.end(), sysReg);
    assert(regItr != sysRegVec.end() &&
           "[SimEng:SimInfo] System register was not defined in the System "
           "Register Vector. Please ensure it is included in "
           "simeng::arch::archInfo::sysRegisterEnums_.");
    return regItr - sysRegVec.begin();
  }

  /** A getter function to retrieve whether or not the special files
   * directories should be generated. */
  static const bool getGenSpecFiles() {
    return getInstance()->genSpecialFiles_;
  }

  /** A utility function to rebuild/construct member variables/classes. For use
   * if the configuration used changes during simulation (e.g. during the
   * execution of a test suite). */
  static void reBuild() { getInstance()->extractValues(); }

 private:
  SimInfo() {
    // Set the validated config file to be the current default config
    // generated by the default constructor of ModelConfig
    validatedConfig_ = modelConfig_.getConfig();
    extractValues();
  }

  /** Gets the static instance of the SimInfo class. */
  static std::unique_ptr<SimInfo>& getInstance() {
    static std::unique_ptr<SimInfo> SimInfoClass = nullptr;
    if (SimInfoClass == nullptr) {
      SimInfoClass = std::unique_ptr<SimInfo>(new SimInfo());
    }
    return SimInfoClass;
  }

  /** Create a model config from a passed YAML file path. */
  void makeConfig(std::string path) {
    // Recreate the model config instance from the YAML file path
    modelConfig_ = ModelConfig(path);

    // Update config path to be the passed path
    configFilePath_ = path;

    // Update the validated config file
    validatedConfig_ = modelConfig_.getConfig();
    extractValues();
  }

  /** A function to extract various values from the generated config file to
   * populate frequently queried model config values. */
  void extractValues() {
    // Get ISA type and set the corresponding ArchInfo class
    std::string isa;
    validatedConfig_["Core"]["ISA"] >> isa;
    if (isa == "AArch64") {
      isa_ = ISA::AArch64;
      archInfo_ = std::make_unique<arch::aarch64::ArchInfo>(
          arch::aarch64::ArchInfo(validatedConfig_));
    } else if (isa == "rv64") {
      isa_ = ISA::RV64;
      archInfo_ = std::make_unique<arch::riscv::ArchInfo>(
          arch::riscv::ArchInfo(validatedConfig_));
    }

    // Get Simulation mode
    std::string mode;
    validatedConfig_["Core"]["Simulation-Mode"] >> mode;
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
    validatedConfig_["CPU-Info"]["Generate-Special-Dir"] >> genSpecialFiles_;
  }

  /** The validated model config file represented as a ryml:Tree. */
  ryml::Tree validatedConfig_;

  /** The ModelConfig instance used to create and maintain the model config
   * file. */
  ModelConfig modelConfig_;

  /** The path of the model config file. Defaults to "Default". */
  std::string configFilePath_ = DEFAULT_STR;

  /** The simulation mode of the current execution of SimEng. */
  SimulationMode mode_;

  /** The simulation mode string of the current execution of SimEng. */
  std::string modeStr_;

  /** The instruction set architecture of the current execution of SimEng. */
  ISA isa_;

  /** Instance of an ArchInfo class used to store architecture specific
   * configuration options. */
  std::unique_ptr<arch::ArchInfo> archInfo_;

  /** A bool representing if the special file directory should be created. */
  bool genSpecialFiles_;
};

}  // namespace config
}  // namespace simeng