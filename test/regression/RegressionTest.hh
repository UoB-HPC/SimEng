#pragma once

#include <memory>

#include "gtest/gtest.h"

#include "ArchitecturalRegisterFileSet.hh"
#include "Core.hh"
#include "arch/Architecture.hh"
#include "kernel/Linux.hh"
#include "kernel/LinuxProcess.hh"
#include "pipeline/PortAllocator.hh"

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

  /** Get a value from process memory at `address`. */
  template <typename T>
  T getMemoryValue(uint64_t address) const {
    EXPECT_LE(address + sizeof(T), processMemorySize_);
    return *(T*)(processMemory_ + address);
  }

  /** The process memory. */
  char* processMemory_ = nullptr;

  /** The size of the process memory in bytes. */
  size_t processMemorySize_ = 0;

  /** The process that was executed. */
  std::unique_ptr<simeng::kernel::LinuxProcess> process_;

  /** The core that was used. */
  std::unique_ptr<simeng::Core> core_ = nullptr;

 private:
  /** Assemble test source to a flat binary for the given triple. */
  void assemble(const char* source, const char* triple);

  /** The flat binary produced by assembling the test source. */
  uint8_t* code_ = nullptr;

  /** The size of the assembled flat binary in bytes. */
  size_t codeSize_ = 0;
};
