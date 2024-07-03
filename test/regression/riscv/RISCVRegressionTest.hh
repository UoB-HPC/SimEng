#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

[[maybe_unused]] static const char* RISCV_ADDITIONAL_CONFIG = R"YAML(
{
  Core:
    {
      Clock-Frequency-GHz: 2.5,
    },
  Register-Set:
    {
      GeneralPurpose-Count: 154,
      FloatingPoint-Count: 90,
    },
  L1-Data-Memory:
    {
      Interface-Type: Flat,
    },
  L1-Instruction-Memory:
    {
      Interface-Type: Flat,
    },
  Ports:
    {
      '0': { Portname: 0, Instruction-Group-Support: [INT, FLOAT, LOAD, STORE, BRANCH] },
    },
}
)YAML";

/** A helper function to convert the supplied parameters of
 * INSTANTIATE_TEST_SUITE_P into test name. */
inline std::string paramToString(
    const testing::TestParamInfo<std::tuple<CoreType, std::string>> val) {
  // Get core type as string
  std::string coreString = "";
  switch (std::get<0>(val.param)) {
    case EMULATION:
      coreString = "emulation";
      break;
    case INORDER:
      coreString = "inorder";
      break;
    case OUTOFORDER:
      coreString = "outoforder";
      break;
    default:
      coreString = "unknown";
      break;
  }
  return coreString;
}

/** A helper macro to run a snippet of RISCV assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros
 * are appended to the source to ensure that the program will terminate with
 * an unallocated instruction encoding exception instead of running into the
 * heap. */
#define RUN_RISCV(source)                             \
  {                                                   \
    std::string sourceWithTerminator = source;        \
    sourceWithTerminator += "\n.word 0";              \
    run(sourceWithTerminator.c_str(), "+m,+a,+f,+d"); \
  }                                                   \
  if (HasFatalFailure()) return

/** A helper macro to run a snippet of RISCV assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros
 * are appended to the source to ensure that the program will terminate with
 * an illegal instruction exception instead of running into the heap. This
 * specifically targets the compressed extension allowing for the RUN_RISCV
 * macro to ignore it, otherwise LLVM eagerly emits compressed instructions for
 * non-compressed assembly. */
#define RUN_RISCV_COMP(source)                           \
  {                                                      \
    std::string sourceWithTerminator = source;           \
    sourceWithTerminator += "\n.word 0";                 \
    run(sourceWithTerminator.c_str(), "+m,+a,+f,+d,+c"); \
  }                                                      \
  if (HasFatalFailure()) return

#define EXPECT_GROUP(source, expectedGroup)                                    \
  {                                                                            \
    std::string sourceWithTerminator = source;                                 \
    sourceWithTerminator += "\n.word 0";                                       \
    checkGroup(sourceWithTerminator.c_str(), expectedGroup, "+m,+a,+f,+d,+c"); \
  }                                                                            \
  if (HasFatalFailure()) return

/** The test fixture for all RISCV regression tests. */
class RISCVRegressionTest : public RegressionTest {
 protected:
  virtual ~RISCVRegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source, const char* extensions);

  void checkGroup(const char* source, const int expectedGroup,
                  const char* extensions) override;

  /** Generate a default YAML-formatted configuration. */
  void generateConfig() const override;

  /** Create an ISA instance from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture(
      simeng::kernel::Linux& kernel) const override;

  /** Get the value of a general purpose register. */
  template <typename T>
  T getGeneralRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::riscv::RegisterType::GENERAL, tag});
  }

  /** Get the value of a floating point register. */
  template <typename T>
  T getFPRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::riscv::RegisterType::FLOAT, tag});
  }

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator(
      ryml::ConstNodeRef config =
          simeng::config::SimInfo::getConfig()) const override;
};