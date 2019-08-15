#pragma once

#include <memory>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/pipeline/PortAllocator.hh"

/** The different types of core model that can be used in tests. */
enum CoreType { EMULATION, INORDER, OUTOFORDER };

/** A helper function to convert a `CoreType` to a human-readable string. */
inline std::string coreTypeToString(
    const testing::TestParamInfo<CoreType> val) {
  switch (val.param) {
    case EMULATION:
      return "emulation";
    case INORDER:
      return "inorder";
    case OUTOFORDER:
      return "outoforder";
    default:
      return "unknown";
  }
}

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
class RegressionTest : public ::testing::TestWithParam<CoreType> {
 protected:
  virtual ~RegressionTest();

  virtual void TearDown() override;

  /** Run the assembly in `source`, building it for the target `triple`. */
  void run(const char* source, const char* triple);

  /** Create an ISA instance from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture(
      simeng::kernel::Linux& kernel) const = 0;

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
    return *(T*)(processMemory_ + address);
  }

  /** The initial data to populate the heap with. */
  std::vector<uint8_t> initialHeapData_;

  /** The maximum number of ticks to run before aborting the test. */
  uint64_t maxTicks_ = UINT64_MAX;

  /** The number of ticks that were run before the test program completed. */
  uint64_t numTicks_ = 0;

  /** The process memory. */
  char* processMemory_ = nullptr;

  /** The size of the process memory in bytes. */
  size_t processMemorySize_ = 0;

  /** The process that was executed. */
  std::unique_ptr<simeng::kernel::LinuxProcess> process_;

  /** The core that was used. */
  std::unique_ptr<simeng::Core> core_ = nullptr;

  /** The output written to stdout during the test. */
  std::string stdout_;

  /** True if the test program finished running. */
  bool programFinished_ = false;

 private:
  /** Assemble test source to a flat binary for the given triple. */
  void assemble(const char* source, const char* triple);

  /** The flat binary produced by assembling the test source. */
  uint8_t* code_ = nullptr;

  /** The size of the assembled flat binary in bytes. */
  size_t codeSize_ = 0;
};
