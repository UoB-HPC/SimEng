#pragma once

#include "simeng/Config.hh"
#include "simeng/RegisterFileSet.hh"

namespace simeng {
enum simMode { emulation, inorder, outoforder };
enum ISA { AArch64, RV64 };

/** A SimInfo class to hold values specific to the current simulation. */
class SimInfo {
 public:
  static simMode getSimMode() { return getInstance()->mode_; }

  static ISA getISA() { return getInstance()->isa_; }

  static const std::vector<simeng::RegisterFileStructure>& getArchRegStruct() {
    return getInstance()->archRegStruct_;
  }

  static const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct() {
    return getInstance()->physRegStruct_;
  }

  static void setArchRegStruct(
      const std::vector<simeng::RegisterFileStructure>& fileStruct) {
    getInstance()->archRegStruct_ = fileStruct;
  }

  static void setPhysRegStruct(
      const std::vector<simeng::RegisterFileStructure>& fileStruct) {
    getInstance()->physRegStruct_ = fileStruct;
  }

 private:
  SimInfo() {
    // Get Config File
    YAML::Node& config = Config::get();
    // Get ISA type
    if (config["Core"]["ISA"].as<std::string>() == "AArch64") {
      isa_ = ISA::AArch64;
    } else if (config["Core"]["ISA"].as<std::string>() == "rv64") {
      isa_ = ISA::RV64;
    }
    // Get Simulation mode
    if (config["Core"]["Simulation-Mode"].as<std::string>() == "emulation") {
      mode_ = simMode::emulation;
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "inorderpipelined") {
      mode_ = simMode::inorder;
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "outoforder") {
      mode_ = simMode::outoforder;
    }

    // Initialise architectural and physical reg structures
    archRegStruct_ = {};
    physRegStruct_ = {};
  };

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

  /** Architecture type of the current execution of SimEng. */
  ISA isa_;

  /** Architectural Register Structure of the current execution of SimEng. */
  std::vector<simeng::RegisterFileStructure> archRegStruct_;

  /** Physical Register Structure of the current execution of SimEng. */
  std::vector<simeng::RegisterFileStructure> physRegStruct_;
};
}  // namespace simeng