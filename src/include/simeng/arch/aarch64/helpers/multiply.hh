#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class multiplyHelp {
 public:
  /** Helper function for instructions with the format `madd rd, rn, rm, ra`.
   * Returns single value. */
  template <typename T>
  static T madd_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a + (n * m));
  }

  /** Helper function for instructions with the format `mul rd, rn, rm`.
   * Returns single value. */
  template <typename T>
  static T mul_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n * m);
  }

  /** Helper function for instructions with the format `msub rd, rn, rm, ra`.
   * Returns single value. */
  template <typename T>
  static T msub_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a - (n * m));
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng