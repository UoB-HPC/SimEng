#pragma once

#include <string>

#include "simeng/AlwaysNotTakenPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/GenericPredictor.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/arch/aarch64/MicroDecoder.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {

enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

/** A class to create a SimEng core instance from a supplied config. */
class CoreInstance {
 public:
  /** Default constructor with a no passed configuration. */
  CoreInstance();

  /** Constructor with a config file path. */
  CoreInstance(std::string configPath);

  /** Constructor with a pre-constructed config file. */
  CoreInstance(YAML::Node config);

  ~CoreInstance();

  /** Construct the SimEng linux process object from an executable ELF file and
   * its command-line arguments. */
  void createProcess(const std::vector<std::string>& commandLine);

  /** Construct the SimEng linux process object from an span of instructions. */
  void createProcess(span<char> instructions);

  /** Construct the SimEng L1 instruction cache memory. */
  std::shared_ptr<simeng::MemoryInterface> createL1InstructionMemory(
      const simeng::MemInterfaceType type);

  /** Set the SimEng L1 instruction cache memory. */
  void setL1InstructionMemory(std::shared_ptr<simeng::MemoryInterface> memRef);

  /** Construct the SimEng L1 data cache memory. */
  std::shared_ptr<simeng::MemoryInterface> createL1DataMemory(
      const simeng::MemInterfaceType type);

  /** Set the SimEng L1 data cache memory. */
  void setL1DataMemory(std::shared_ptr<simeng::MemoryInterface> memRef);

  /** Construct the core and all its associated simulation objects. */
  std::shared_ptr<simeng::Core> createCore();

  /** Construct the special file directory. */
  void createSpecialFileDirectory();

  /** Getter for the set simulation mode. */
  const SimulationMode getSimulationMode() const;

 private:
  /** Extract simulation mode from config file. */
  void setSimulationMode();

  /** Construct the process memory from the generated process_ object. */
  void createProcessMemory();

  /** The config file describing the modelled core to be created. */
  YAML::Node config_;

  /** Reference to the SimEng linux process object. */
  std::unique_ptr<simeng::kernel::LinuxProcess> process_ = nullptr;

  /** The size of the process memory. */
  size_t processMemorySize_;

  /** The process memory space. */
  char* processMemory_;

  /** The SimEng kernel object. */
  simeng::kernel::Linux kernel_;

  /** Reference to the SimEng architecture object. */
  std::unique_ptr<simeng::arch::Architecture> arch_ = nullptr;

  /** Reference to the SimEng branch predictor object. */
  std::unique_ptr<simeng::BranchPredictor> predictor_ = nullptr;

  /** Reference to the SimEng port allocator object. */
  std::unique_ptr<simeng::pipeline::PortAllocator> portAllocator_ = nullptr;

  /** Reference to the SimEng core object. */
  std::shared_ptr<simeng::Core> core_ = nullptr;

  /** The simulation mode in use, defaulting to emulation. */
  SimulationMode mode_ = SimulationMode::Emulation;

  /** Reference to the SimEng instruction memory object. */
  std::shared_ptr<simeng::MemoryInterface> instructionMemory_ = nullptr;

  /** Reference to the SimEng data memory object. */
  std::shared_ptr<simeng::MemoryInterface> dataMemory_ = nullptr;
};

}  // namespace simeng
