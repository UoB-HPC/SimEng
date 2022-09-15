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

// Out-of-order test; counts down from 1024*1024, with an independent `orr`
// at the start of each branch. With an instruction latency of 2 or greater,
// the `orr` at the start of the next loop should issue/execute while the
// preceding branch is waiting on the result from the `subs`.
uint32_t hex_[] = {
    0x320C03E0,  // orr w0, wzr, #1048576
    0x320003E1,  // orr w0, wzr, #1
    0x71000400,  // subs w0, w0, #1
    0x54FFFFC1,  // b.ne -8
                 // .exit:
    0xD2800000,  // mov x0, #0
    0xD2800BC8,  // mov x8, #94
    0xD4000001,  // svc #0
};

namespace simeng {

/** The available modes of simulation. */
enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

/** A class to create a SimEng core instance from a supplied config. */
class CoreInstance {
 public:
  /** Default constructor with command line arguments but no passed
   * configuration. */
  CoreInstance(int argc, char** argv);

  /** Constructor with with command line arguments and a configuration file
   * path. */
  CoreInstance(int argc, char** argv, std::string configPath);

  ~CoreInstance();

  /** Set the SimEng L1 instruction cache memory. */
  void setL1InstructionMemory(std::shared_ptr<simeng::MemoryInterface> memRef);

  /** Set the SimEng L1 data cache memory. */
  void setL1DataMemory(std::shared_ptr<simeng::MemoryInterface> memRef);

  /** Construct the core and all its associated simulation objects after the
   * process and memory interfaces have been instantiated. */
  void createCore();

  /** Getter for the set simulation mode. */
  const SimulationMode getSimulationMode() const;

  /** Getter for the create core object. */
  std::shared_ptr<simeng::Core> getCore() const;

  /** Getter for the create data memory object. */
  std::shared_ptr<simeng::MemoryInterface> getDataMemory() const;

  /** Getter for the create instruction memory object. */
  std::shared_ptr<simeng::MemoryInterface> getInstructionMemory() const;

  /** Getter for a shared pointer to the created process image. */
  std::shared_ptr<char> getProcessImage() const;

  /** Getter for the size of the created process image. */
  const uint64_t getProcessImageSize() const;

 private:
  /** Generate the appropriate simulation objects as parameterised by the
   * configuration.*/
  void generateCoreModel(int argc, char** argv);

  /** Extract simulation mode from config file. */
  void setSimulationMode();

  /** Construct the SimEng linux process object from command line arguments.
   * Empty command line arguments denote the usage of hardcoded
   * instructions held in the hex_ array. */
  void createProcess(int argc, char** argv);

  /** Construct the process memory from the generated process_ object. */
  void createProcessMemory();

  /** Construct the SimEng L1 instruction cache memory. */
  void createL1InstructionMemory(const simeng::MemInterfaceType type);

  /** Construct the SimEng L1 data cache memory. */
  void createL1DataMemory(const simeng::MemInterfaceType type);

  /** Construct the special file directory. */
  void createSpecialFileDirectory();

  /** The config file describing the modelled core to be created. */
  YAML::Node config_;

  /** Reference to the SimEng linux process object. */
  std::unique_ptr<simeng::kernel::LinuxProcess> process_ = nullptr;

  /** The size of the process memory. */
  uint64_t processMemorySize_;

  /** The process memory space. */
  std::shared_ptr<char> processMemory_;

  /** The SimEng Linux kernel object. */
  simeng::kernel::Linux kernel_;

  /** Whether or not the createCore() function must be manually called. */
  bool manualCreateCore_ = false;

  /** Whether or not the dataMemory_ must be set manually. */
  bool setDataMemory_ = false;

  /** Whether or not the instructionMemory_ must be set manually. */
  bool setInstructionMemory_ = false;

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

  /** Reference to the SimEng data memory object. */
  std::shared_ptr<simeng::MemoryInterface> dataMemory_ = nullptr;

  /** Reference to the SimEng instruction memory object. */
  std::shared_ptr<simeng::MemoryInterface> instructionMemory_ = nullptr;
};

}  // namespace simeng
