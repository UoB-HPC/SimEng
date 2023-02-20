#pragma once

#include <string>

#include "simeng/Config.hh"
#include "simeng/RegisterFileSet.hh"

namespace simeng {
/** Enum representing the possible simulation modes. */
enum simMode { emulation, inorder, outoforder };

/** Enum representing the possible ISAs. */
enum ISA { AArch64, RV64 };

/** A SimInfo class to hold values specific to the current simulation. */
class SimInfo {
 public:
  static simMode getSimMode() { return getInstance()->mode_; }

  static std::string getSimModeStr() { return getInstance()->modeStr_; }

  static ISA getISA() { return getInstance()->isa_; }

  static const std::vector<simeng::RegisterFileStructure>& getArchRegStruct() {
    return getInstance()->archRegStruct_;
  }

  static const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct() {
    return getInstance()->physRegStruct_;
  }

  static const std::vector<arm64_sysreg>& getSysRegVec() {
    return getInstance()->sysRegisterEnums_;
  }

  static const bool getGenSpecFiles() {
    return getInstance()->genSpecialFiles_;
  }

  // static void setArchRegStruct(
  //     const std::vector<simeng::RegisterFileStructure>& fileStruct) {
  //   getInstance()->archRegStruct_ = fileStruct;
  // }

  // static void setPhysRegStruct(
  //     const std::vector<simeng::RegisterFileStructure>& fileStruct) {
  //   getInstance()->physRegStruct_ = fileStruct;
  // }

 private:
  SimInfo() {
    // Get Config File
    YAML::Node& config = Config::get();
    // Get ISA type
    if (config["Core"]["ISA"].as<std::string>() == "AArch64") {
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
      // Initialise architectural and physical reg structures
      archRegStruct_ = {};
      physRegStruct_ = {};
    } else if (config["Core"]["ISA"].as<std::string>() == "rv64") {
      isa_ = ISA::RV64;
      // Define system registers
      sysRegisterEnums_ = {};
      // Initialise architectural and physical reg structures
      archRegStruct_ = {};
      physRegStruct_ = {};
    }

    // Get Simulation mode
    if (config["Core"]["Simulation-Mode"].as<std::string>() == "emulation") {
      mode_ = simMode::emulation;
      modeStr_ = "Emulation";
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "inorderpipelined") {
      mode_ = simMode::inorder;
      modeStr_ = "In-Order Pipelined";
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "outoforder") {
      mode_ = simMode::outoforder;
      modeStr_ = "Out-of-Order";
    }

    // Get if special files directory should be created
    genSpecialFiles_ = config["CPU-Info"]["Generate-Special-Dir"].as<bool>();
  }

  /** Gets the static instance of the SimInfo class. */
  static std::unique_ptr<SimInfo>& getInstance() {
    static std::unique_ptr<SimInfo> SimInfoClass = nullptr;
    if (SimInfoClass == nullptr) {
      SimInfoClass = std::unique_ptr<SimInfo>(new SimInfo());
    }
    return SimInfoClass;
  }

  /** The simulation mode of current execution of SimEng. */
  simMode mode_;

  /** The simulation mode String of current execution of SimEng. */
  std::string modeStr_;

  /** Architecture type of the current execution of SimEng. */
  ISA isa_;

  /** Architectural Register Structure of the current execution of SimEng. */
  std::vector<simeng::RegisterFileStructure> archRegStruct_;

  /** Physical Register Structure of the current execution of SimEng. */
  std::vector<simeng::RegisterFileStructure> physRegStruct_;

  /** Vector of all system register Capsone enum values used in Architecture. */
  std::vector<arm64_sysreg> sysRegisterEnums_;

  /** Bool representing if the special file directory should be created. */
  bool genSpecialFiles_;
};
}  // namespace simeng