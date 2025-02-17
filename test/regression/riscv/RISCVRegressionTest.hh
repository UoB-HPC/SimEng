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

/** A helper macro to run a snippet of RISC-V assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros
 * are appended to the source to ensure that the program will terminate with
 * an unallocated instruction encoding exception instead of running into the
 * heap. */
#define RUN_RISCV(source)                      \
  {                                            \
    std::string sourceWithTerminator = source; \
    sourceWithTerminator += "\n.word 0";       \
    run(sourceWithTerminator.c_str(), false);  \
  }                                            \
  if (HasFatalFailure()) return

/** A helper macro to run a snippet of RISC-V assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros
 * are appended to the source to ensure that the program will terminate with
 * an illegal instruction exception instead of running into the heap. This
 * specifically targets the compressed extension allowing for the RUN_RISCV
 * macro to ignore it, otherwise LLVM eagerly emits compressed instructions for
 * non-compressed assembly. */
#define RUN_RISCV_COMP(source)                 \
  {                                            \
    std::string sourceWithTerminator = source; \
    sourceWithTerminator += "\n.word 0";       \
    run(sourceWithTerminator.c_str(), true);   \
  }                                            \
  if (HasFatalFailure()) return

/** A helper macro to predecode the first instruction in a snippet of RISC-V
 * assembly code and check the assigned group(s) for each micro-op matches the
 * expected group(s). Returns from the calling function if a fatal error occurs.
 * Four bytes containing zeros are appended to the source to ensure that the
 * program will terminate with an unallocated instruction encoding exception
 * instead of running into the heap.
 */
#define EXPECT_GROUP(source, ...)                                   \
  {                                                                 \
    std::string sourceWithTerminator = source;                      \
    sourceWithTerminator += "\n.word 0";                            \
    checkGroup(sourceWithTerminator.c_str(), {__VA_ARGS__}, false); \
  }                                                                 \
  if (HasFatalFailure()) return

/** A helper macro to predecode the first instruction in a snippet of RISC-V
 * assembly code and check the assigned group(s) for each micro-op matches the
 * expected group(s). Returns from the calling function if a fatal error occurs.
 * Four bytes containing zeros are appended to the source to ensure that the
 * program will terminate with an unallocated instruction encoding exception
 * instead of running into the heap. This specifically targets the compressed
 * extension allowing for the EXPECT_GROUP macro to ignore it, otherwise LLVM
 * eagerly emits compressed instructions for non-compressed assembly. */
#define EXPECT_GROUP_COMP(source, ...)                             \
  {                                                                \
    std::string sourceWithTerminator = source;                     \
    sourceWithTerminator += "\n.word 0";                           \
    checkGroup(sourceWithTerminator.c_str(), {__VA_ARGS__}, true); \
  }                                                                \
  if (HasFatalFailure()) return

/** The test fixture for all RISC-V regression tests. */
class RISCVRegressionTest : public RegressionTest {
 protected:
  virtual ~RISCVRegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source, bool compressed);

  /** Run the first instruction in source through predecode and check the
   * groups. */
  void checkGroup(const char* source,
                  const std::vector<uint16_t>& expectedGroups, bool compressed);

  /** Generate a default YAML-formatted configuration. */
  void generateConfig() const override;

  /** Instantiate an ISA specific architecture from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> instantiateArchitecture(
      simeng::kernel::Linux& kernel) const override;

  /** Initialise LLVM */
  void initialiseLLVM() {
    LLVMInitializeRISCVTargetInfo();
    LLVMInitializeRISCVTargetMC();
    LLVMInitializeRISCVAsmParser();
  }

  /** Get subtarget feature string. Use compressed instructions only if
   * requested */
  std::string getSubtargetFeaturesString(bool compressed) {
    std::string subtargetFeatures = "+m,+a,+f,+d";
    if (compressed) {
      subtargetFeatures.append(",+c");
    }
    return subtargetFeatures;
  }

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