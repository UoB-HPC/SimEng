#pragma once

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"

#if defined(__clang__)
// Prevent errors due to warnings in included file when using clang
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wall"
#endif

#include "llvm/MC/MCContext.h"

#if defined(__clang__)
// Allow errors again
#pragma clang diagnostic pop
#endif

#include "llvm/MC/MCInstrInfo.h"
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCParser/MCAsmParser.h"
#include "llvm/MC/MCParser/MCTargetAsmParser.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/MC/MCStreamer.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/TargetSelect.h"
#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/pipeline/PortAllocator.hh"
#include "simeng/version.hh"

#if SIMENG_LLVM_VERSION < 14
#include "llvm/Support/TargetRegistry.h"
#else
#include "llvm/MC/TargetRegistry.h"
#endif

/** The different types of core model that can be used in tests. */
enum CoreType { EMULATION, INORDER, OUTOFORDER };

/** The base class for all regression tests.
 *
 * This is a googletest fixture which is parameterisable on a builtin core
 * model type. Subclasses will override routines that require
 * architecture-specific knowledge.
 *
 * This class is responsible for assembling test source and running the
 * resulting flat binary through an instance of the target core model. Helper
 * methods are provided to query the state of the core and memory after
 * execution has completed.
 */
class RegressionTest
    : public ::testing::TestWithParam<std::tuple<CoreType, std::string>> {
 protected:
  virtual ~RegressionTest();

  virtual void TearDown() override;

  /** Generate a default YAML-formatted configuration. */
  virtual void generateConfig() const = 0;

  /** Instantiate an ISA specific architecture from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> instantiateArchitecture(
      simeng::kernel::Linux& kernel) const = 0;

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator(
      ryml::ConstNodeRef config =
          simeng::config::SimInfo::getConfig()) const = 0;

  /** Create the kernel then instantiate an ISA specific architecture. Populates
   * the architecture_ member variable. */
  void createArchitecture(const char* source, const char* triple,
                          const char* extensions);

  /** Run the assembly in `source`, building it for the target `triple` and ISA
   * extensions. */
  void run(const char* source, const char* triple, const char* extensions);

  /** Predecode the first instruction in source and check the assigned group
   * matches the expectation. */
  void checkGroup(const char* source, const char* triple,
                  const char* extensions,
                  const std::vector<uint16_t>& expectedGroups);

  /** Get the value of an architectural register. */
  template <typename T>
  T getRegister(simeng::Register reg) const {
    return core_->getArchitecturalRegisterFileSet().get(reg).get<T>();
  }

  /** Get a pointer to the value of an architectural vector register. */
  template <typename T>
  const T* getVectorRegister(simeng::Register reg) const {
    return core_->getArchitecturalRegisterFileSet().get(reg).getAsVector<T>();
  }

  /** Get a value from process memory at `address`. */
  template <typename T>
  T getMemoryValue(uint64_t address) const {
    EXPECT_LE(address + sizeof(T), processMemorySize_);
    T dest{};
    std::memcpy(&dest, processMemory_ + address, sizeof(T));
    return dest;
  }

  /** The initial data to populate the heap with. */
  std::vector<uint8_t> initialHeapData_;

  /** The process to be executed. */
  std::unique_ptr<simeng::kernel::LinuxProcess> process_;

  /** The process memory. */
  char* processMemory_ = nullptr;

  /** The output written to stdout during the test. */
  std::string stdout_;

  /** The flat binary produced by assembling the test source. */
  uint8_t* code_ = nullptr;

  /** The number of ticks that were run before the test program completed. */
  uint64_t numTicks_ = 0;

  /** The maximum number of ticks to run before aborting the test. */
  uint64_t maxTicks_ = UINT64_MAX;

  /** Pointer to be instantiated for the architecture. */
  std::unique_ptr<simeng::arch::Architecture> architecture_ = nullptr;

 private:
  /** Assemble test source to a flat binary for the given triple and ISA
   * extensions. */
  void assemble(const char* source, const char* triple, const char* extensions);

  /** Instantiate the core according to the config. */
  void createCore(const char* source, const char* triple,
                  const char* extensions);

  /* Pointer to be instantiated for the kernel. */
  std::unique_ptr<simeng::kernel::Linux> kernel_ = nullptr;

  /* Pointer to be instantiated for the port allocator. */
  std::unique_ptr<simeng::pipeline::PortAllocator> portAllocator_ = nullptr;

  /* Pointer to be instantiated for the branch predictor. */
  std::unique_ptr<simeng::BranchPredictor> predictor_ = nullptr;

  /** All possible data memory interfaces. dataMemory_ set to one of these
   * depending on core type. */
  std::unique_ptr<simeng::memory::MemoryInterface> flatDataMemory_ = nullptr;
  std::unique_ptr<simeng::memory::MemoryInterface> fixedLatencyDataMemory_ =
      nullptr;

  /** Pointer to be instantiated for the data memory interface. */
  std::unique_ptr<simeng::memory::MemoryInterface> dataMemory_ = nullptr;

  /** Pointer to be instantiated for the instruction memory interface. */
  std::unique_ptr<simeng::memory::MemoryInterface> instructionMemory_ = nullptr;

  /** Pointer to be instantiated for the core. */
  std::unique_ptr<simeng::Core> core_ = nullptr;

  /** The size of the process memory in bytes. */
  size_t processMemorySize_ = 0;

  /** True if the test program finished running. */
  bool programFinished_ = false;

  /** The size of the assembled flat binary in bytes. */
  size_t codeSize_ = 0;

  /** The entry point of the process. */
  uint64_t entryPoint_ = 0;
};
