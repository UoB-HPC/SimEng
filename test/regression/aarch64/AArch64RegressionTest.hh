#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

#define AARCH64_CONFIG                                                        \
  ("{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "               \
   "Timer-Frequency: 100, Micro-Operations: False}, Fetch: "                  \
   "{Fetch-Block-Size: 32, Loop-Buffer-Size: 64, Loop-Detection-Threshold: "  \
   "4}, Process-Image: {Heap-Size: 100000, Stack-Size: 100000}, "             \
   "Register-Set: {GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90, "  \
   "Predicate-Count: 17, Conditional-Count: 128, MatrixRow-Count: 256}, "     \
   "Pipeline-Widths: { Commit: 4, FrontEnd: 4, LSQ-Completion: 2}, "          \
   "Queue-Sizes: {ROB: 180, Load: 64, Store: 36}, Branch-Predictor: "         \
   "{BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, Global-History-Length: 10, " \
   "RAS-entries: 5, Fallback-Static-Predictor: 2}, Data-Memory: "             \
   "{Interface-Type: Flat}, Instruction-Memory: {Interface-Type: Flat}, "     \
   "LSQ-L1-Interface: {Access-Latency: 4, Exclusive: False, Load-Bandwidth: " \
   "32, Store-Bandwidth: 16, Permitted-Requests-Per-Cycle: 2, "               \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "    \
   "{'0': {Portname: Port 0, Instruction-Group-Support: [0, 14, 52, 66, 67, " \
   "70, 71]}}, Reservation-Stations: {'0': {Size: 60, Dispatch-Rate: 4, "     \
   "Ports: [0]}}, Execution-Units: {'0': {Pipelined: true}}}")

/** A helper function to convert the supplied parameters of
 * INSTANTIATE_TEST_SUITE_P into test name. */
inline std::string paramToString(
    const testing::TestParamInfo<std::tuple<CoreType, YAML::Node>> val) {
  YAML::Node config = YAML::Load(AARCH64_CONFIG);

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
  // Get vector length as string
  std::string vectorLengthString = "";
  if (std::get<1>(val.param)["Vector-Length"].IsDefined() &&
      !(std::get<1>(val.param)["Vector-Length"].IsNull())) {
    vectorLengthString =
        "WithVL" + std::get<1>(val.param)["Vector-Length"].as<std::string>();
  }
  return coreString + vectorLengthString;
}

/** A helper function to generate all coreType vector-length pairs. */
inline std::vector<std::tuple<CoreType, YAML::Node>> genCoreTypeVLPairs(
    CoreType type) {
  std::vector<std::tuple<CoreType, YAML::Node>> coreVLPairs;
  for (uint64_t i = 128; i <= 2048; i += 128) {
    YAML::Node vlNode;
    vlNode["Vector-Length"] = i;
    coreVLPairs.push_back(std::make_tuple(type, vlNode));
  }
  return coreVLPairs;
}

/** A helper macro to run a snippet of Armv9.2-a assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros are
 * appended to the source to ensure that the program will terminate with an
 * illegal instruction exception instead of running into the heap. */
#define RUN_AARCH64(source)                    \
  {                                            \
    std::string sourceWithTerminator = source; \
    sourceWithTerminator += "\n.word 0";       \
    run(sourceWithTerminator.c_str());         \
  }                                            \
  if (HasFatalFailure()) return

/** Check each element of a Neon register against expected values.
 *
 * The `tag` argument is the register index, and the `type` argument is the C++
 * data type to use for value comparisons. The third argument should be an
 * initializer list containing one value for each register element (for a total
 * of `(256 / sizeof(type))` values).
 *
 * For example:
 *
 *     // Compare v2.4s to some expected 32-bit floating point values.
 *     CHECK_NEON(2, float, {123.456f, 0.f, 42.f, -1.f});
 */
#define CHECK_NEON(tag, type, ...)             \
  {                                            \
    SCOPED_TRACE("<<== error generated here"); \
    checkNeonRegister<type>(tag, __VA_ARGS__); \
  }

/** Check each element of a Predicate register against expected values.
 *
 * The `tag` argument is the register index, and the `type` argument is the C++
 * data type to use for value comparisons. The third argument should be an
 * initializer list containing one value for each register element (for a total
 * of `(32 / sizeof(type))` values).
 *
 * For example:
 *
 *     // Compare p1.s to some expected 32-bit unsigned integer values.
 *     // Where VL = 4 and all elements are set to true.
 *     CHECK_PREDICATE(1, uint32_t, {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
 * 0x11});
 */
#define CHECK_PREDICATE(tag, type, ...)             \
  {                                                 \
    SCOPED_TRACE("<<== error generated here");      \
    checkPredicateRegister<type>(tag, __VA_ARGS__); \
  }

/** The test fixture for all AArch64 regression tests. */
class AArch64RegressionTest : public RegressionTest {
 protected:
  virtual ~AArch64RegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source);

  /** Generate a default YAML-formatted configuration. */
  YAML::Node generateConfig() const override;

  /** Create an ISA instance from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture(
      simeng::kernel::Linux& kernel, YAML::Node config) const override;

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator()
      const override;

  /** Check the elements of a Neon register.
   *
   * This should be invoked via the `CHECK_NEON` macro in order to provide
   * better diagnostic messages, rather than called directly from test code.
   */
  template <typename T>
  void checkNeonRegister(uint8_t tag,
                         const std::array<T, (256 / sizeof(T))>& values) const {
    const T* data = RegressionTest::getVectorRegister<T>(
        {simeng::arch::aarch64::RegisterType::VECTOR, tag});
    for (unsigned i = 0; i < (256 / sizeof(T)); i++) {
      EXPECT_NEAR(data[i], values[i], 0.0005)
          << "Mismatch for element " << i << ".";
    }
  }

  /** Check the elements of a Predicate register.
   *
   * This should be invoked via the `CHECK_PREDICATE` macro in order to provide
   * better diagnostic messages, rather than called directly from test code.
   */
  template <typename T>
  void checkPredicateRegister(
      uint8_t tag, const std::array<T, (32 / sizeof(T))>& values) const {
    const T* data = RegressionTest::getVectorRegister<T>(
        {simeng::arch::aarch64::RegisterType::PREDICATE, tag});
    for (unsigned i = 0; i < (32 / sizeof(T)); i++) {
      EXPECT_NEAR(data[i], values[i], 0.0005)
          << "Mismatch for element " << i << ".";
    }
  }

  /** Get the value of a general purpose register. */
  template <typename T>
  T getGeneralRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::aarch64::RegisterType::GENERAL, tag});
  }

  /** Get the value of a system register. */
  uint64_t getSystemRegister(uint16_t encoding) const {
    auto arch = reinterpret_cast<simeng::arch::aarch64::Architecture*>(
        architecture_.get());
    return getRegister<uint64_t>(
        {simeng::arch::aarch64::RegisterType::SYSTEM,
         static_cast<uint16_t>(arch->getSystemRegisterTag(encoding))});
  }

  /** Get the value of a vector register element. */
  template <typename T, unsigned element>
  T getVectorRegisterElement(uint8_t tag) const {
    static_assert(element * sizeof(T) < 256);
    return RegressionTest::getVectorRegister<T>(
        {simeng::arch::aarch64::RegisterType::VECTOR, tag})[element];
  }

  /** Get the value of the NZCV register. */
  uint8_t getNZCV() const;

  /** Get the negative flag from the NZCV register. */
  bool getNegativeFlag() const;

  /** Get the zero flag from the NZCV register. */
  bool getZeroFlag() const;

  /** Get the carry flag from the NZCV register. */
  bool getCarryFlag() const;

  /** Get the overflow flag from the NZCV register. */
  bool getOverflowFlag() const;

  /** Generate an array representing a NEON register from a source vector and a
   * number of elements defined by a number of bytes used. */
  template <typename T>
  std::array<T, (256 / sizeof(T))> fillNeon(std::vector<T> src,
                                            int num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (256 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by cycling through source elements
    for (int i = 0; i < (num_bytes / sizeof(T)); i++) {
      generatedArray[i] = src[i % src.size()];
    }
    return generatedArray;
  }

  /** Generate an array representing a NEON register by combining two source
   * vectors and a number of elements defined by a number of bytes used. */
  template <typename T>
  std::array<T, (256 / sizeof(T))> fillNeonCombined(std::vector<T> srcA,
                                                    std::vector<T> srcB,
                                                    int num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (256 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by cycling through source elements
    int num_elements = (num_bytes / sizeof(T)) / 2;
    for (int i = 0; i < num_elements; i++) {
      generatedArray[i] = srcA[i % srcA.size()];
      generatedArray[i + num_elements] = srcB[i % srcB.size()];
    }
    return generatedArray;
  }

  /** Generate an array representing a NEON register from a base value and an
   * offset. */
  template <typename T>
  std::array<T, (256 / sizeof(T))> fillNeonBaseAndOffset(T base, T offset,
                                                         int num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (256 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by adding an increasing offset value to the base value
    for (int i = 0; i < (num_bytes / sizeof(T)); i++) {
      generatedArray[i] = base + (i * offset);
    }
    return generatedArray;
  }

  /** Fill an array dest of T entries, representing the initialHeapData_, from a
   * source vector and a number of entries. */
  template <typename T>
  void fillHeap(T* dest, std::vector<T> src, int entries) const {
    // Fill destination by cycling through source elements
    for (int i = 0; i < entries; i++) {
      dest[i] = src[i % src.size()];
    }
  }

  /** Fill an array dest of T entries, representing the initialHeapData_, by
   * combining two source vectors and a number of entries. */
  template <typename T>
  void fillHeapCombined(T* dest, std::vector<T> srcA, std::vector<T> srcB,
                        int entries) const {
    // Fill destination by cycling through source elements
    for (int i = 0; i < entries / 2; i++) {
      dest[i] = srcA[i % srcA.size()];
      dest[i + (entries / 2)] = srcB[i % srcB.size()];
    }
  }

  /** Generate an array representing a PREDICATE register from a number of
   * lanes, a pattern and a vector arrangement used in bytes. */
  std::array<uint64_t, 4> fillPred(int num_lanes, std::vector<uint8_t> pattern,
                                   int byte_arrangement) const {
    // Create array to be returned and fill with a default value of 0
    std::array<uint64_t, 4> generatedArray;
    generatedArray.fill(0);
    // Get number of lanes accounting for byte_arrangement
    int grouped_lanes = (num_lanes % byte_arrangement != 0)
                            ? std::ceil((double)num_lanes / byte_arrangement)
                            : (num_lanes / byte_arrangement);
    // Activate number of lanes
    for (int i = 0; i < grouped_lanes; i++) {
      if (pattern[i % pattern.size()]) {
        generatedArray[(int)(i * byte_arrangement) / 64] |=
            1ull << ((i * byte_arrangement) % 64);
      }
    }
    return generatedArray;
  }

  /** Generate an array representing a PREDICATE register from a source vector
   * and a number of elements defined by a number of bytes used. */
  template <typename T>
  std::array<T, (32 / sizeof(T))> fillPredFromSource(std::vector<T> src,
                                                     int num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (32 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by cycling through source elements
    for (int i = 0; i < (num_bytes / sizeof(T)); i++) {
      generatedArray[i] = src[i % src.size()];
    }
    return generatedArray;
  }

  /** Generate an array representing a PREDICATE register by combining two
   * source vectors and a number of elements defined by a number of bytes used.
   */
  template <typename T>
  std::array<T, (32 / sizeof(T))> fillPredFromTwoSources(std::vector<T> srcA,
                                                         std::vector<T> srcB,
                                                         int num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (32 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by cycling through source elements
    int num_elements = (num_bytes / sizeof(T)) / 2;
    for (int i = 0; i < num_elements; i++) {
      generatedArray[i] = srcA[i % srcA.size()];
      generatedArray[i + num_elements] = srcB[i % srcB.size()];
    }
    return generatedArray;
  }

  /** The current vector-length being used by the test suite. */
  const uint64_t VL =
      (std::get<1>(GetParam())["Vector-Length"].IsDefined() &&
       !(std::get<1>(GetParam())["Vector-Length"].IsNull()))
          ? std::get<1>(GetParam())["Vector-Length"].as<uint64_t>()
          : 0;
};