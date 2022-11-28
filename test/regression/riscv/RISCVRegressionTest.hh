#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

#define RISCV_CONFIG                                                           \
  ("{Core: {ISA: rv64, Simulation-Mode: emulation, Clock-Frequency: 2.5}, "    \
   "Fetch: {Fetch-Block-Size: 32, Loop-Buffer-Size: 64, "                      \
   "Loop-Detection-Threshold: 4}, Process-Image: {Heap-Size: 100000, "         \
   "Stack-Size: 100000}, Register-Set: {GeneralPurpose-Count: 154, "           \
   "FloatingPoint-Count: 90}, Pipeline-Widths: {Commit: 4, Dispatch-Rate: 4, " \
   "FrontEnd: 4, LSQ-Completion: 2}, Queue-Sizes: {ROB: 180, Load: 64, "       \
   "Store: 36}, Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: "  \
   "2, Global-History-Length: 10, RAS-entries: 5, Fallback-Static-Predictor: " \
   "0}, L1-Data-Memory: {Interface-Type: Fixed}, L1-Instruction-Memory: "      \
   "{Interface-Type: Flat}, LSQ-L1-Interface: {Access-Latency: 4, Exclusive: " \
   "False, Load-Bandwidth: 32, Store-Bandwidth: 16, "                          \
   "Permitted-Requests-Per-Cycle: 2, Permitted-Loads-Per-Cycle: 2, "           \
   "Permitted-Stores-Per-Cycle: 1}, Ports: {'0': {Portname: Port 0, "          \
   "Instruction-Group-Support: [0, 10, 11, 12 ]}}, Reservation-Stations: "     \
   "{'0': {Size: 60, Dispatch-Rate: 4, Ports: [0]}}, Execution-Units: "        \
   "{'0': {Pipelined: true}}}")

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

/** A helper macro to run a snippet of RISCV assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros
 * are appended to the source to ensure that the program will terminate with
 * an illegal instruction exception instead of running into the heap. */
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