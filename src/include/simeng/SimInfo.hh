#pragma once

#include <iostream>
#include <string>

#include "simeng/Instruction.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/RegisterFileSet.hh"
#include "simeng/ryml.hh"

namespace simeng {

#define DEFAULT_STR "Default"

/** Enum representing the possible simulation modes. */
enum simMode { emulation, inorder, outoforder };

/** Enum representing the possible ISAs. */
enum ISA { AArch64, RV64 };

/** A SimInfo class to hold values, specified by the constructed ryml::Tree
 * object in the ModelConfig class and manually, used after the instantiation of
 * the current simulation and its objects. */
class SimInfo {
 public:
  /** A getter function to retrieve the ryml::Tree representing the underlying
   * model config file. */
  static ryml::Tree getConfig() { return getInstance()->validatedConfig_; }

  /** A setter function to set the model config file from a path to a YAML file.
   */
  static void setConfig(std::string path) { getInstance()->makeConfig(path); }

  /** A function to add additional config values to the model config file. */
  static void addToConfig(std::string configAdditions) {
    getInstance()->mdlCnf_.addConfigOptions(configAdditions);
    // Replace the validated config with new instance with the supplied
    // additional values
    getInstance()->validatedConfig_ = getInstance()->mdlCnf_.getConfig();
  }

  /** A function to generate a default config file based on a passed ISA. */
  static void generateDefault(ISA isa) {
    if (isa == ISA::AArch64)
      getInstance()->mdlCnf_.reGenerateDefault("AArch64");
    else if (isa == ISA::RV64)
      getInstance()->mdlCnf_.reGenerateDefault("rv64");

    // Replace the validated config with the new default config
    getInstance()->validatedConfig_ = getInstance()->mdlCnf_.getConfig();
    // Update previoulsy extracted values from the config file
    getInstance()->extractValues();
  }

  /** A utility function to get a value, of a specified type, from a config
   * option. */
  template <typename T>
  static T getValue(ryml::NodeRef node) {
    T val;
    node >> val;
    return val;
  }

  /** A getter function to retrieve the config file path. */
  static std::string getConfigPath() { return getInstance()->configFilePath_; }

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance. */
  static simMode getSimMode() { return getInstance()->mode_; }

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance as a string. */
  static std::string getSimModeStr() { return getInstance()->modeStr_; }

  /** A getter function to retrieve which ISA the current simulation is using.
   */
  static ISA getISA() { return getInstance()->isa_; }

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available architectural registers. */
  static const std::vector<simeng::RegisterFileStructure>& getArchRegStruct() {
    return getInstance()->archRegStruct_;
  }

  /** A getter function to retrieve a vector of Capstone arm64_sysreg enums for
   * all the system registers that should be utilised in simulation. */
  static const std::vector<arm64_sysreg>& getSysRegVec() {
    return getInstance()->sysRegisterEnums_;
  }

  /** A getter function to retrieve whether or not the special files directories
   * should be generated. */
  static const bool getGenSpecFiles() {
    return getInstance()->genSpecialFiles_;
  }

  /** A function used to reset the architectural register file structure. */
  static void resetArchRegs() { getInstance()->resetArchRegStruct(); }

  static void printConfig() {
    getInstance()->mdlCnf_.recursivePrint(
        getInstance()->validatedConfig_.rootref());
  }

 private:
  SimInfo() {
    // Set the validated config file to be the current default config generated
    // by the default constructor of ModelConfig
    validatedConfig_ = mdlCnf_.getConfig();
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
    mdlCnf_ = simeng::ModelConfig(path);
    // Update the validated config file
    validatedConfig_ = mdlCnf_.getConfig();
    extractValues();
  }

  /** A function to extract various values from the generated config file to
   * populate frequently queried model config values. */
  void extractValues() {
    // Get ISA type and set the corresponding architectural fileset
    std::string isa;
    validatedConfig_["Core"]["ISA"] >> isa;
    if (isa == "AArch64") {
      isa_ = ISA::AArch64;
      // Define system registers
      sysRegisterEnums_ = {arm64_sysreg::ARM64_SYSREG_DCZID_EL0,
                           arm64_sysreg::ARM64_SYSREG_FPCR,
                           arm64_sysreg::ARM64_SYSREG_FPSR,
                           arm64_sysreg::ARM64_SYSREG_TPIDR_EL0,
                           arm64_sysreg::ARM64_SYSREG_MIDR_EL1,
                           arm64_sysreg::ARM64_SYSREG_CNTVCT_EL0,
                           arm64_sysreg::ARM64_SYSREG_PMCCNTR_EL0,
                           arm64_sysreg::ARM64_SYSREG_SVCR};
      // Initialise architectural reg structures
      uint16_t numSysRegs = static_cast<uint16_t>(sysRegisterEnums_.size());
      // Set the size of SME ZA in bytes by dividing the SVL by 8
      uint16_t ZAbits;
      validatedConfig_["Core"]["Streaming-Vector-Length"] >> ZAbits;
      const uint16_t ZAsize = ZAbits / 8;
      archRegStruct_ = {
          {8, 32},          // General purpose
          {256, 32},        // Vector
          {32, 17},         // Predicate
          {1, 1},           // NZCV
          {8, numSysRegs},  // System
          {256, ZAsize},    // Matrix (Each row is a register)
      };
    } else if (isa == "rv64") {
      isa_ = ISA::RV64;
      // Define system registers
      sysRegisterEnums_ = {};
      // Initialise architectural reg structures
      uint16_t numSysRegs = static_cast<uint16_t>(sysRegisterEnums_.size());
      archRegStruct_ = {
          {8, 32},          // General purpose
          {8, 32},          // Floating Point
          {8, numSysRegs},  // System
      };
    }

    // Get Simulation mode
    std::string mode;
    validatedConfig_["Core"]["Simulation-Mode"] >> mode;
    if (mode == "emulation") {
      mode_ = simMode::emulation;
      modeStr_ = "Emulation";
    } else if (mode == "inorderpipelined") {
      mode_ = simMode::inorder;
      modeStr_ = "In-Order Pipelined";
    } else if (mode == "outoforder") {
      mode_ = simMode::outoforder;
      modeStr_ = "Out-of-Order";
    }

    // Get if the special files directory should be created
    validatedConfig_["CPU-Info"]["Generate-Special-Dir"] >> genSpecialFiles_;
  }

  /** Function used to reset the architectural register file structure. */
  void resetArchRegStruct() {
    // Given some register quantities rely on Config file arguments (SME
    // relies on SVL), it is possible that if the config was to change the
    // register quantities would be incorrect. This function provides a way to
    // reset the Architectural register structure.
    if (isa_ == ISA::AArch64) {
      uint16_t numSysRegs = static_cast<uint16_t>(sysRegisterEnums_.size());
      // Set the size of SME ZA in bytes by dividing the SVL by 8
      uint16_t ZAbits;
      validatedConfig_["Core"]["Streaming-Vector-Length"] >> ZAbits;
      const uint16_t ZAsize = ZAbits / 8;
      archRegStruct_ = {
          {8, 32},          // General purpose
          {256, 32},        // Vector
          {32, 17},         // Predicate
          {1, 1},           // NZCV
          {8, numSysRegs},  // System
          {256, ZAsize},    // Matrix (Each row is a register)
      };
    } else if (isa_ == ISA::RV64) {
      uint16_t numSysRegs = static_cast<uint16_t>(sysRegisterEnums_.size());
      archRegStruct_ = {
          {8, 32},          // General purpose
          {8, 32},          // Floating Point
          {8, numSysRegs},  // System
      };
    }
  }

  /** The validated model config file represented as a ryml:Tree. */
  ryml::Tree validatedConfig_;

  /** The ModelConfig instance used to create and maintain the model config
   * file. */
  simeng::ModelConfig mdlCnf_;

  /** The path of the model config file. Defaults to "Default". */
  std::string configFilePath_ = "Default";

  /** The simulation mode of the current execution of SimEng. */
  simMode mode_;

  /** The simulation mode string of the current execution of SimEng. */
  std::string modeStr_;

  /** The instruction set architecture of the current execution of SimEng. */
  ISA isa_;

  /** The architectural register structure of the current execution of SimEng.
   */
  std::vector<simeng::RegisterFileStructure> archRegStruct_;

  /** The vector of all system register Capstone enum values used in the
   * associated Architecture class. */
  std::vector<arm64_sysreg> sysRegisterEnums_;

  /** A bool representing if the special file directory should be created. */
  bool genSpecialFiles_;
};
}  // namespace simeng