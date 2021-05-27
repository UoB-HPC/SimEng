#pragma once

#include "RegressionTest.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

#define TX2_CONFIG                                                             \
  ("{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "                \
   "Fetch-Block-Size: 32}, Register-Set: {GeneralPurpose-Count: "              \
   "154, FloatingPoint/SVE-Count: 90, Predicate-Count: 17, "                   \
   "Conditional-Count: 128}, Pipeline-Widths: { Commit: 4, Dispatch-Rate: 4, " \
   "FrontEnd: 4, LSQ-Completion: 2}, Queue-Sizes: {ROB: 180, Load: 64, "       \
   "Store: 36}, Branch-Predictor: {BTB-bitlength: 16}, L1-Cache: "             \
   "{GeneralPurpose-Latency: 4, FloatingPoint-Latency: 4, SVE-Latency: 1, "    \
   "Bandwidth: 32, Permitted-Requests-Per-Cycle: 2, "                          \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "     \
   "{'0': {Portname: Port 0, Instruction-Support: [0, 3, 5, 8, 9, 10, 13, "    \
   "14]}, '1': {Portname: Port 1, Instruction-Support: [0, 3, 4, 5, 8, 9, "    \
   "10, 13, 14]}, '2': {Portname: Port 2, Instruction-Support: [0, 3, 25]}, "  \
   "'3': {Portname: Port 4, Instruction-Support: [15]}, '4': {Portname: Port " \
   "5, Instruction-Support: [15]}, '5': {Portname: Port 3, "                   \
   "Instruction-Support: [20]}}, Reservation-Stations: {'0': {Size: 60, "      \
   "Ports: [0, 1, 2, 3, 4, 5]}}, Execution-Units: {'0': {Pipelined: true}, "   \
   "'1': {Pipelined: true}, '2': {Pipelined: true}, '3': {Pipelined: true}, "  \
   "'4': {Pipelined: true}, '5': {Pipelined: true}}}")

/** A helper macro to run a snippet of Armv8 assembly code, returning from the
 * calling function if a fatal error occurs. Four bytes containing zeros are
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
    uint16_t tag = arch->getSystemRegisterTag(encoding);
    return getRegister<uint64_t>(
        {simeng::arch::aarch64::RegisterType::SYSTEM, tag});
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
};