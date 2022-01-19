#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class floatHelp {
 public:
  /** Helper function for instructions with the format `fabd rd, rn, rm`.
   */
  template <typename T>
  static RegisterValue fabd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fabs(n - m), 256};
  }

  /** Helper function for instructions with the format `fabs vd, vn`.
   */
  template <typename T>
  static RegisterValue fabs_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    return {std::fabs(n), 256};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng