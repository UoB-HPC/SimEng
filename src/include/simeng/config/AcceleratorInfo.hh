#pragma once

#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/ArchInfo.hh"
#include "simeng/config/AcceleratorType.hh"
#include "simeng/config/ModelConfig.hh"
#include "simeng/config/SimulationMode.hh"
#include "simeng/config/yaml/ryml.hh"

namespace simeng {
namespace config {

/** An Accelerator class to hold values, specified by the constructed ryml::Tree
 * object in the ModelConfig class and AcceleratorType. */
class AcceleratorInfo {
 public:
  /** Creates a new AcceleratorInfo object that will model an accelerator
   * of the provided type and using a configuration at the provided path. */
  explicit AcceleratorInfo(const std::string& configPath);

  /** A getter function to retrieve the ryml::Tree representing the underlying
   * model config file. */
  ryml::ConstNodeRef getConfig() const;

  /** A getter function to retrieve the config file path. */
  const std::string& getConfigPath() const noexcept;

  /** A getter function to retrieve the type of the accelerator to model. */
  AcceleratorType getType() const noexcept;

  /** A getter function to retrieve the type of the accelerator in printable
   * form. */
  const char* getTypeString() const;

  /** A getter function to retrieve the simulation mode of the current SimEng
   * instance. */
  SimulationMode getSimMode() const noexcept;

  /** A getter function to retrieve the simulation mode in printable form. */
  const std::string& getSimModeString() const;

  /** A getter function to retrieve which ISA the accelerator is using. */
  ISA getISA() const noexcept;

  /** A getter function to retrieve the used ISA in printable form. */
  const std::string& getISAString() const;

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available architectural registers. */
  const std::vector<RegisterFileStructure>& getArchRegStruct() const;

  /** A getter function to retrieve a vector of {size, number} pairs describing
   * the available physical registers. */
  const std::vector<RegisterFileStructure>& getPhysRegStruct() const;

  /** A getter function to retrieve a vector of uint16_t values describing
   * the quantities of physical registers available. */
  const std::vector<uint16_t>& getPhysRegQuantities() const;

  /** A getter function to retrieve a vector of Capstone sysreg enums for
   * all the system registers that should be utilised in simulation. */
  const std::vector<uint64_t>& getSysRegVec() const;

 private:
  /** The type of the accelerator to model. */
  AcceleratorType type_;

  /** The validated model config file represented as a ryml:Tree. */
  ryml::Tree validatedConfig_;

  /** The ModelConfig instance used to create and maintain the model config
   * file. */
  ModelConfig modelConfig_;

  /** The path of the model config file. */
  std::string configFilePath_;

  /** The simulation mode of the current execution of SimEng. */
  SimulationMode simMode_;

  /** The printable form of the simulation mode. */
  std::string simModeString_;

  /** The instruction set architecture of the accelerator. */
  ISA isa_;

  /** The printable form of the ISA. */
  std::string isaString_;

  /** Instance of an ArchInfo class used to store architecture specific
   * configuration options. */
  std::unique_ptr<arch::ArchInfo> archInfo_;
};

}  // namespace config
}  // namespace simeng
