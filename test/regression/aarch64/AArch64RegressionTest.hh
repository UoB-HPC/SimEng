#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

[[maybe_unused]] static const char* AARCH64_ADDITIONAL_CONFIG = R"YAML(
{
  Core:
    {
      Clock-Frequency-GHz: 2.5,
    },
  Register-Set:
    {
      GeneralPurpose-Count: 154,
      FloatingPoint/SVE-Count: 90,
      Predicate-Count: 17, 
      Conditional-Count: 128,
      Matrix-Count: 2,
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
      '0': { Portname: 0, Instruction-Group-Support: [INT, FP, SVE, PREDICATE, LOAD, STORE, BRANCH, SME] },
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
  // Get vector length as string
  std::string vectorLengthString = "";
  // Temporarily construct a ryml::Tree to extract config options as strings
  ryml::Tree tempTree =
      ryml::parse_in_arena(ryml::to_csubstr(std::get<1>(val.param)));
  if (tempTree.rootref().has_child("Core")) {
    if (tempTree.rootref()["Core"].has_child("Vector-Length")) {
      vectorLengthString +=
          "WithVL" + tempTree["Core"]["Vector-Length"].as<std::string>();
    }
    if (tempTree.rootref()["Core"].has_child("Streaming-Vector-Length")) {
      vectorLengthString +=
          "WithSVL" +
          tempTree["Core"]["Streaming-Vector-Length"].as<std::string>();
    }
  }
  return coreString + vectorLengthString;
}

/** A helper function to generate all coreType vector-length pairs. */
inline std::vector<std::tuple<CoreType, std::string>> genCoreTypeVLPairs(
    CoreType type) {
  std::vector<std::tuple<CoreType, std::string>> coreVLPairs;
  for (uint64_t i = 128; i <= 2048; i += 128) {
    coreVLPairs.push_back(std::make_tuple(
        type,
        "{Core: {Vector-Length: " + std::to_string(i) +
            "}, LSQ-L1-Interface: {Load-Bandwidth: " + std::to_string(i / 8) +
            ", Store-Bandwidth: " + std::to_string(i / 8) + "}}"));
  }
  return coreVLPairs;
}

/** A helper function to generate all coreType streaming-vector-length pairs. */
inline std::vector<std::tuple<CoreType, std::string>> genCoreTypeSVLPairs(
    CoreType type) {
  std::vector<std::tuple<CoreType, std::string>> coreSVLPairs;
  for (uint64_t i = 128; i <= 2048; i *= 2) {
    coreSVLPairs.push_back(std::make_tuple(
        type,
        "{Core: {Streaming-Vector-Length: " + std::to_string(i) +
            "}, LSQ-L1-Interface: {Load-Bandwidth: " + std::to_string(i / 8) +
            ", Store-Bandwidth: " + std::to_string(i / 8) + "}}"));
  }
  return coreSVLPairs;
}

/** A helper macro to run a snippet of Armv9.2-a assembly code, returning from
 * the calling function if a fatal error occurs. Four bytes containing zeros are
 * appended to the source to ensure that the program will terminate with an
 * unallocated instruction encoding exception instead of running into the heap.
 */
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

/** Check each element of a Matrix register row against expected values.
 *
 * The `tag` argument is the register tile the row is contained in, the `index`
 * argument is the exact row within the selected tile,  and the `type` argument
 * is the C++ data type to use for value comparisons. The third argument should
 * be an initializer list containing one value for each register element (for a
 * total of `(256 / sizeof(type))` values).
 *
 * For example:
 *
 *     // Compare za1h.s[0] to some expected 32-bit floating point values.
 *     CHECK_MAT_ROW(ARM64_REG_ZAS1, 0, float, {123.456f, 0.f, 42.f, -1.f});
 */
#define CHECK_MAT_ROW(tag, index, type, ...)               \
  {                                                        \
    SCOPED_TRACE("<<== error generated here");             \
    checkMatrixRegisterRow<type>(tag, index, __VA_ARGS__); \
  }

/** Check each element of a Matrix register column against expected values.
 *
 * The `tag` argument is the register tile the column is contained in, the
 * `index` argument is the exact column within the selected tile,  and the
 * `type` argument is the C++ data type to use for value comparisons. The third
 * argument should be an initializer list containing one value for each register
 * element (for a total of `(256 / sizeof(type))` values).
 *
 * For example:
 *
 *     // Compare za1v.s[0] to some expected 32-bit floating point values.
 *     CHECK_MAT_COL(ARM64_REG_ZAS1, 0, float, {123.456f, 0.f, 42.f, -1.f});
 */
#define CHECK_MAT_COL(tag, index, type, ...)               \
  {                                                        \
    SCOPED_TRACE("<<== error generated here");             \
    checkMatrixRegisterCol<type>(tag, index, __VA_ARGS__); \
  }

/** A helper macro to predecode the first instruction in a snippet of Armv9.2-a
 * assembly code and check the assigned group(s) for each micro-op matches the
 * expected group(s). Returns from the calling function if a fatal error occurs.
 * Four bytes containing zeros are appended to the source to ensure that the
 * program will terminate with an unallocated instruction encoding exception
 * instead of running into the heap.
 */
#define EXPECT_GROUP(source, ...)                            \
  {                                                          \
    std::string sourceWithTerminator = source;               \
    sourceWithTerminator += "\n.word 0";                     \
    checkGroup(sourceWithTerminator.c_str(), {__VA_ARGS__}); \
  }                                                          \
  if (HasFatalFailure()) return

/** The test fixture for all AArch64 regression tests. */
class AArch64RegressionTest : public RegressionTest {
 protected:
  virtual ~AArch64RegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source);

  /** Run the first instruction in source through predecode and check the
   * groups. */
  void checkGroup(const char* source,
                  const std::vector<uint16_t>& expectedGroups);

  /** Generate a default YAML-formatted configuration. */
  void generateConfig() const override;

  /** Instantiate an ISA specific architecture from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> instantiateArchitecture(
      simeng::kernel::Linux& kernel) const override;

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator(
      ryml::ConstNodeRef config =
          simeng::config::SimInfo::getConfig()) const override;

  /** Initialise LLVM */
  void initialiseLLVM() {
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64AsmParser();
  }

  /** Get the subtarget feature string based on LLVM version being used */
  std::string getSubtargetFeaturesString() {
#if SIMENG_LLVM_VERSION < 14
    return "+sve,+lse";
#else
    return "+sve,+lse,+sve2,+sme,+sme-f64";
#endif
  }

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

  /** Check the elements of a Matrix register row (one row from ZA).
   *
   * This should be invoked via the `CHECK_MAT_ROW` macro in order to provide
   * better diagnostic messages, rather than called directly from test code.
   */
  template <typename T>
  void checkMatrixRegisterRow(
      uint16_t tag, uint16_t index,
      const std::array<T, (256 / sizeof(T))>& values) const {
    // Get matrix row register tag
    uint8_t base = 0;
    uint8_t tileTypeCount = 0;
    if (tag == ARM64_REG_ZA || tag == ARM64_REG_ZAB0) {
      // Treat ZA as byte tile : ZAB0 represents whole matrix, only 1 tile
      // Add all rows for this SVL
      // Don't need to set base as will always be 0
      tileTypeCount = 1;
    } else if (tag >= ARM64_REG_ZAH0 && tag <= ARM64_REG_ZAH1) {
      base = tag - ARM64_REG_ZAH0;
      tileTypeCount = 2;
    } else if (tag >= ARM64_REG_ZAS0 && tag <= ARM64_REG_ZAS3) {
      base = tag - ARM64_REG_ZAS0;
      tileTypeCount = 4;
    } else if (tag >= ARM64_REG_ZAD0 && tag <= ARM64_REG_ZAD7) {
      base = tag - ARM64_REG_ZAD0;
      tileTypeCount = 8;
    } else if (tag >= ARM64_REG_ZAQ0 && tag <= ARM64_REG_ZAQ15) {
      base = tag - ARM64_REG_ZAQ0;
      tileTypeCount = 16;
    }
    uint16_t reg_tag = base + (index * tileTypeCount);

    const T* data = getMatrixRegisterRow<T>(reg_tag);
    for (unsigned i = 0; i < (256 / sizeof(T)); i++) {
      EXPECT_NEAR(data[i], values[i], 0.0005)
          << "Mismatch for element " << i << ".";
    }
  }

  /** Check the elements of a Matrix register row (one row from ZA).
   *
   * This should be invoked via the `CHECK_MAT_ROW` macro in order to provide
   * better diagnostic messages, rather than called directly from test code.
   */
  template <typename T>
  void checkMatrixRegisterCol(
      uint16_t tag, uint16_t index,
      const std::array<T, (256 / sizeof(T))>& values) const {
    // Get matrix row register tag
    uint8_t base = 0;
    uint8_t tileTypeCount = 0;
    if (tag == ARM64_REG_ZA || tag == ARM64_REG_ZAB0) {
      // Treat ZA as byte tile : ZAB0 represents whole matrix, only 1 tile
      // Add all rows for this SVL
      // Don't need to set base as will always be 0
      tileTypeCount = 1;
    } else if (tag >= ARM64_REG_ZAH0 && tag <= ARM64_REG_ZAH1) {
      base = tag - ARM64_REG_ZAH0;
      tileTypeCount = 2;
    } else if (tag >= ARM64_REG_ZAS0 && tag <= ARM64_REG_ZAS3) {
      base = tag - ARM64_REG_ZAS0;
      tileTypeCount = 4;
    } else if (tag >= ARM64_REG_ZAD0 && tag <= ARM64_REG_ZAD7) {
      base = tag - ARM64_REG_ZAD0;
      tileTypeCount = 8;
    } else if (tag >= ARM64_REG_ZAQ0 && tag <= ARM64_REG_ZAQ15) {
      base = tag - ARM64_REG_ZAQ0;
      tileTypeCount = 16;
    }

    for (unsigned i = 0; i < (SVL / (sizeof(T) * 8)); i++) {
      uint16_t reg_tag = base + (i * tileTypeCount);
      const T data_i = getMatrixRegisterRow<T>(reg_tag)[index];
      EXPECT_NEAR(data_i, values[i], 0.0005)
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

  /** Get a pointer to the value of an architectural matrix register row. */
  template <typename T>
  const T* getMatrixRegisterRow(uint16_t tag) const {
    return RegressionTest::getVectorRegister<T>(
        {simeng::arch::aarch64::RegisterType::MATRIX, tag});
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
  std::array<T, (256 / sizeof(T))> fillNeon(const std::vector<T>& src,
                                            uint32_t num_bytes) const {
    // Create array to be returned and fill with a default value of 0
    std::array<T, (256 / sizeof(T))> generatedArray;
    generatedArray.fill(0);
    // Fill array by cycling through source elements
    for (size_t i = 0; i < (num_bytes / sizeof(T)); i++) {
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
    for (size_t i = 0; i < (num_bytes / sizeof(T)); i++) {
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

  /** A function to get the current vector length from the test config string if
   * present (defaults to 0). */
  uint64_t getVL() {
    uint64_t VL = 0;
    // Temporarily construct a ryml::Tree to extract the VL
    ryml::Tree tempTree =
        ryml::parse_in_arena(ryml::to_csubstr(std::get<1>(GetParam())));
    if (tempTree.rootref().has_child("Core") &&
        tempTree.rootref()["Core"].has_child("Vector-Length")) {
      VL = tempTree["Core"]["Vector-Length"].as<uint64_t>();
    }
    return VL;
  }

  /** A function to get the current streaming vector length from the test config
   * string if present (defaults to 0). */
  uint64_t getSVL() {
    uint64_t SVL = 0;
    // Temporarily construct a ryml::Tree to extract the SVL
    ryml::Tree tempTree =
        ryml::parse_in_arena(ryml::to_csubstr(std::get<1>(GetParam())));
    if (tempTree.rootref().has_child("Core") &&
        tempTree.rootref()["Core"].has_child("Streaming-Vector-Length")) {
      SVL = tempTree["Core"]["Streaming-Vector-Length"].as<uint64_t>();
    }
    return SVL;
  }

  /** The current vector-length being used by the test suite. */
  const uint64_t VL = getVL();

  /** The current streaming-vector-length being used by the test suite. */
  const uint64_t SVL = getSVL();
};
