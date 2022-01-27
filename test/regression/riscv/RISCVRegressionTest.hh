#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

// TODO currently set up for Aarch64 e.g. SVE-Count
#define RISCV_CONFIG                                                          \
  ("{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "               \
   "Fetch-Block-Size: 32}, Process-Image: {Heap-Size: 100000, Stack-Size: "   \
   "100000}, Register-Set: {GeneralPurpose-Count: 154, "                      \
   "FloatingPoint/SVE-Count: 90, Predicate-Count: 17, Conditional-Count: "    \
   "128}, Pipeline-Widths: { Commit: 4, Dispatch-Rate: 4, FrontEnd: 4, "      \
   "LSQ-Completion: 2}, Queue-Sizes: {ROB: 180, Load: 64, Store: 36}, "       \
   "Branch-Predictor: {BTB-bitlength: 16}, L1-Cache: {Access-Latency: 4, "    \
   "Bandwidth: 32, Permitted-Requests-Per-Cycle: 2, "                         \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "    \
   "{'0': {Portname: Port 0, Instruction-Group-Support: [0, 12, 46, 58, 59, " \
   "60, 61]}}, Reservation-Stations: {'0': {Size: 60, Ports: [0]}}, "         \
   "Execution-Units: {'0': {Pipelined: true}}}")

/** A helper function to convert the supplied parameters of
 * INSTANTIATE_TEST_SUITE_P into test name. */
inline std::string paramToString(
    const testing::TestParamInfo<std::tuple<CoreType, YAML::Node>> val) {
  YAML::Node config = YAML::Load(RISCV_CONFIG);

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

/** A helper macro to run a snippet of RISCV assembly code, returning from the
 * calling function if a fatal error occurs. Four bytes containing zeros are
 * appended to the source to ensure that the program will terminate with an
 * illegal instruction exception instead of running into the heap. */
#define RUN_RISCV(source)                      \
  {                                            \
    std::string sourceWithTerminator = source; \
    sourceWithTerminator += "\n.word 0";       \
    run(sourceWithTerminator.c_str());         \
  }                                            \
  if (HasFatalFailure()) return

/** The test fixture for all RISCV regression tests. */
class RISCVRegressionTest : public RegressionTest {
 protected:
  virtual ~RISCVRegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source);

  /** Generate a default YAML-formatted configuration. */
  YAML::Node generateConfig() const override;

  /** Create an ISA instance from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture(
      simeng::kernel::Linux& kernel, YAML::Node config) const override;

  /** Get the value of a general purpose register. */
  template <typename T>
  T getGeneralRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::riscv::RegisterType::GENERAL, tag});
  }

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator()
      const override;
};