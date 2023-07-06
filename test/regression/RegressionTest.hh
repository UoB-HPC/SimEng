#pragma once

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCContext.h"
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
#include "simeng/OS/Constants.hh"
#include "simeng/OS/Process.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/OS/SyscallHandler.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/memory/Mem.hh"
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
    : public ::testing::TestWithParam<std::tuple<CoreType, YAML::Node>> {
 protected:
  virtual ~RegressionTest();

  virtual void TearDown() override;

  /** Generate a default YAML-formatted configuration. */
  virtual YAML::Node generateConfig() const = 0;

  /** Run the assembly in `source`, building it for the target `triple` and ISA
   * extensions. */
  void run(const char* source, const char* triple, const char* extensions);

  /** Create an ISA instance. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture()
      const = 0;

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator()
      const = 0;

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
    uint64_t addr = process_->translate(address);
    if (simeng::OS::masks::faults::hasFault(addr)) {
      std::cout << stdout_ << std::endl;
      std::cout << "[SimEng:RegressionTest] Translation fault in "
                   "getMemoryValue for address: "
                << address << std::endl;
      std::exit(1);
    }
    std::vector<char> mem = memory_->getUntimedData(addr, sizeof(T));
    T dest{};
    std::memcpy(&dest, mem.data(), sizeof(T));
    return dest;
  }

  /** The initial data to populate the heap with. */
  std::vector<char> initialHeapData_;

  /** The maximum number of ticks to run before aborting the test. */
  uint64_t maxTicks_ = UINT64_MAX;

  /** The number of ticks that were run before the test program completed. */
  uint64_t numTicks_ = 0;

  /** The architecture instance. */
  std::unique_ptr<simeng::arch::Architecture> architecture_;

  std::shared_ptr<simeng::memory::Mem> memory_;

  /** The size of the process memory in bytes. */
  size_t processMemorySize_ = 0;

  /** The process that was executed. */
  std::shared_ptr<simeng::OS::Process> process_;

  /** The core model used to execute the test code. */
  std::shared_ptr<simeng::Core> core_ = nullptr;

  /** The output written to stdout during the test. */
  std::string stdout_;

  /** True if the test program finished running. */
  bool programFinished_ = false;

 private:
  /** Assemble test source to a flat binary for the given triple and ISA
   * extensions. */
  void assemble(const char* source, const char* triple, const char* extensions);

  /** The flat binary produced by assembling the test source. */
  uint8_t* code_ = nullptr;

  /** The size of the assembled flat binary in bytes. */
  size_t codeSize_ = 0;
};
