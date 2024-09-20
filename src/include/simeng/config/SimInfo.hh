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
  static ryml::ConstNodeRef getConfig();

  /** A setter function to set the model config file from a path to a YAML file.
   */
  static void setConfig(std::string path);

  /** A function to add additional config values to the model config file. */
  static void addToConfig(std::string configAdditions);

  /** A function to generate a default config file based on a passed ISA. */
  static void generateDefault(ISA isa, bool force = false);

  /** A getter function to retrieve the config file path. */
  static std::string getConfigPath();

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance. */
  static SimulationMode getSimMode();

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance as a string. */
  static std::string getSimModeStr();

  /** A getter function to retrieve which ISA the current simulation is using.
   */
  static ISA getISA();

  /** A getter function to retrieve which ISA the current simulation is using in
   * a string format. */
  static std::string getISAString();

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available architectural registers. */
  static const std::vector<simeng::RegisterFileStructure>& getArchRegStruct();

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available physical registers. */
  static const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct();

  /** A getter function to retrieve a vector of uint16_t values describing
   * the quantities of physical registers available. */
  static const std::vector<uint16_t>& getPhysRegQuantities();

  /** A getter function to retrieve a vector of Capstone sysreg enums for
   * all the system registers that should be utilised in simulation. */
  static const std::vector<uint64_t>& getSysRegVec();

  /** A getter function to retrieve whether or not the special files
   * directories should be generated. */
  static bool getGenSpecFiles();

  /** A utility function to rebuild/construct member variables/classes. For use
   * if the configuration used changes during simulation (e.g. during the
   * execution of a test suite). */
  static void reBuild();

 private:
  SimInfo();

  /** Gets the static instance of the SimInfo class. */
  static std::unique_ptr<SimInfo>& getInstance();

  /** Create a model config from a passed YAML file path. */
  void makeConfig(std::string path);

  /** A function to extract various values from the generated config file to
   * populate frequently queried model config values. */
  void extractValues();

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

  /** The instruction set architecture of the current execution of SimEng in a
   * string format. */
  std::string isaString_;

  /** Instance of an ArchInfo class used to store architecture specific
   * configuration options. */
  std::unique_ptr<arch::ArchInfo> archInfo_;

  /** A bool representing if the special file directory should be created. */
  bool genSpecialFiles_;
};

}  // namespace config
}  // namespace simeng