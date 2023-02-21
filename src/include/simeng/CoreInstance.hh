#pragma once

#include <string>

#include "simeng/AlwaysNotTakenPredictor.hh"
#include "simeng/Config.hh"
#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/GenericPredictor.hh"
#include "simeng/OS/SyscallHandler.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/Mem.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

namespace simeng {

// Forward declare everything needed for SimOS
namespace OS {
class SimOS;
}  // namespace OS

/** The available modes of simulation. */
enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

/** A class to create a SimEng core instance from a supplied config. */
class CoreInstance {
 public:
  /** Constructor with an executable, its arguments, and a model configuration.
   */
  CoreInstance(std::shared_ptr<OS::SyscallHandler> syscallHandler,
               std::shared_ptr<simeng::memory::Mem> mem,
               std::shared_ptr<memory::MMU> mmu);

  // IGNORING SST RELATED CODE FOR NOW
  /** CoreInstance with source code assembled by LLVM and a model configuration.
   */
  // CoreInstance(char* assembledSource, size_t sourceSize,
  //              std::string configPath);

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

  /** Getter for the set simulation mode in a string format. */
  const std::string getSimulationModeString() const;

  /** Getter for the create core object. */
  std::shared_ptr<simeng::Core> getCore() const;

  /** Getter for the create data memory object. */
  std::shared_ptr<simeng::MemoryInterface> getDataMemory() const;

  /** Getter for the create instruction memory object. */
  std::shared_ptr<simeng::MemoryInterface> getInstructionMemory() const;

 private:
  /** Generate the appropriate simulation objects as parameterised by the
   * configuration.*/
  void generateCoreModel();

  /** Extract simulation mode from config file. */
  void setSimulationMode();

  /** Construct the SimEng L1 instruction cache memory. */
  void createL1InstructionMemory(const simeng::MemInterfaceType type);

  /** Construct the SimEng L1 data cache memory. */
  void createL1DataMemory(const simeng::MemInterfaceType type);

  /** Whether or not the source has been assembled by LLVM. */
  bool assembledSource_ = false;

  /** Reference to source assembled by LLVM. */
  char* source_ = nullptr;

  /** Size of the source code assembled by LLVM. */
  size_t sourceSize_ = 0;

  /** The config file describing the modelled core to be created. */
  YAML::Node& config_;

  /** Reference to the SimEng SimOS Process object. */
  std::shared_ptr<simeng::OS::Process> process_ = nullptr;

  /** Reference to the SyscallHandler object in SimOS instance. */
  std::shared_ptr<OS::SyscallHandler> syscallHandler_;

  /** The size of the process memory. */
  uint64_t processMemorySize_;

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

  /** A string format for the simulation mode in use, defaulting to emulation.
   */
  std::string modeString_ = "Emulation";

  /** Reference to the SimEng data memory object. */
  std::shared_ptr<simeng::MemoryInterface> dataMemory_ = nullptr;

  /** Reference to the SimEng instruction memory object. */
  std::shared_ptr<simeng::MemoryInterface> instructionMemory_ = nullptr;

  /** Reference to the simulation memory shared pointer */
  std::shared_ptr<simeng::memory::Mem> memory_ = nullptr;

  /** Reference to the MMU */
  std::shared_ptr<simeng::memory::MMU> mmu_ = nullptr;
};

}  // namespace simeng
