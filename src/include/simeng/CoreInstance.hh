#pragma once

#include <string>

#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/branchpredictors/AlwaysNotTakenPredictor.hh"
#include "simeng/branchpredictors/GenericPredictor.hh"
#include "simeng/branchpredictors/PerceptronPredictor.hh"
#include "simeng/branchpredictors/TAGEPredictor.hh"
#include "simeng/config/AcceleratorType.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/memory/FixedLatencyMemoryInterface.hh"
#include "simeng/memory/FlatMemoryInterface.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "simeng/pipeline/M1PortAllocator.hh"

namespace simeng {

/** A class to create a SimEng core instance from a supplied config. */
class CoreInstance {
 public:
  /** Default constructor with an executable and its arguments. */
  CoreInstance(const std::string& executablePath,
               const std::vector<std::string>& executableArgs,
               ryml::ConstNodeRef config = config::SimInfo::getConfig());

  /** CoreInstance with source code assembled by LLVM and a model configuration.
   */
  CoreInstance(uint8_t* assembledSource, size_t sourceSize,
               ryml::ConstNodeRef config = config::SimInfo::getConfig());

  ~CoreInstance();

  /** Set the SimEng L1 instruction cache memory. */
  void setL1InstructionMemory(std::shared_ptr<memory::MemoryInterface> memRef);

  /** Set the SimEng L1 data cache memory. */
  void setL1DataMemory(std::shared_ptr<memory::MemoryInterface> memRef);

  /** Configure external accelerators. The order in this list determines
   * the order in which an instruction will be tested whether it should
   * be offloaded to a given accelerator. The list should not contain
   * duplicates. */
  void setOffloadingLogic(std::vector<config::AcceleratorType> accelerators,
                          Accelerator::gateway_t::send_fn_t sendFn,
                          Accelerator::gateway_t::receive_fn_t recvFn);

  /** Construct the core and all its associated simulation objects after the
   * process and memory interfaces have been instantiated. */
  void createCore();

  /** Getter for the core object. */
  std::shared_ptr<Core> getCore() const;

  /** Getter for the data memory object. */
  std::shared_ptr<memory::MemoryInterface> getDataMemory() const;

  /** Getter for the instruction memory object. */
  std::shared_ptr<memory::MemoryInterface> getInstructionMemory() const;

  /** Getter for a shared pointer to the created process image. */
  std::shared_ptr<char> getProcessImage() const;

  /** Getter for the size of the created process image. */
  uint64_t getProcessImageSize() const;

  /* Getter for heap start. */
  uint64_t getHeapStart() const;

  /** Getter for the architecture object. */
  const arch::Architecture& getArch() const;

 private:
  /** Generate the appropriate simulation objects as parameterised by the
   * configuration.*/
  void generateCoreModel(const std::string& executablePath,
                         const std::vector<std::string>& executableArgs);

  /** Construct the SimEng linux process object from command line arguments.
   * Empty command line arguments denote the usage of hardcoded
   * instructions held in the hex_ array. */
  void createProcess(const std::string& executablePath,
                     const std::vector<std::string>& executableArgs);

  /** Construct the process memory from the generated process_ object. */
  void createProcessMemory();

  /** Construct the SimEng L1 instruction cache memory. */
  void createL1InstructionMemory(memory::MemInterfaceType type);

  /** Construct the SimEng L1 data cache memory. */
  void createL1DataMemory(memory::MemInterfaceType type);

  /** Construct the special file directory. */
  void createSpecialFileDirectory();

  /** Selects an accelerator from externalAccelerators_ to which the provided
   * instruction should be offloaded. If no accelerator matches,
   * `Undefined` is returned. */
  config::AcceleratorType acceleratorSelector(const Instruction& insn) const;

  /** The config file describing the modelled core to be created. */
  ryml::ConstNodeRef config_;

  /** The SimEng Linux kernel object. */
  kernel::Linux kernel_;

  /** Reference to source assembled by LLVM. */
  uint8_t* source_ = nullptr;

  /** Size of the source code assembled by LLVM. */
  size_t sourceSize_ = 0;

  /** Whether the source has been assembled by LLVM. */
  bool assembledSource_ = false;

  /** Reference to the SimEng linux process object. */
  std::unique_ptr<kernel::LinuxProcess> process_ = nullptr;

  /** The size of the process memory. */
  uint64_t processMemorySize_ = 0;

  /** The process memory space. */
  std::shared_ptr<char> processMemory_ = nullptr;

  /** Whether the dataMemory_ must be set manually. */
  bool setDataMemory_ = false;

  /** Whether the instructionMemory_ must be set manually. */
  bool setInstructionMemory_ = false;

  /** Reference to the SimEng architecture object. */
  std::unique_ptr<arch::Architecture> arch_ = nullptr;

  /** Reference to the SimEng branch predictor object. */
  std::unique_ptr<BranchPredictor> predictor_ = nullptr;

  /** Reference to the SimEng port allocator object. */
  std::unique_ptr<pipeline::PortAllocator> portAllocator_ = nullptr;

  /** The SimEng core object. */
  std::shared_ptr<Core> core_ = nullptr;

  /** Pointer to the SimEng data memory object. */
  std::shared_ptr<memory::MemoryInterface> dataMemory_ = nullptr;

  /** Pointer to the SimEng instruction memory object. */
  std::shared_ptr<memory::MemoryInterface> instructionMemory_ = nullptr;

  /** A list of external accelerators connected to the core. */
  std::vector<config::AcceleratorType> externalAccelerators_;
};

}  // namespace simeng
