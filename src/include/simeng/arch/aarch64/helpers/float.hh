#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class floatHelp {
 public:
  /** Helper function for instructions with the format `fabd vd, vn, vm`.
   */
  template <typename T>
  static std::array<T, 256> fabd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    std::array<T, 256> out = {0};
    out[0] = std::fabs(n - m);
    return out;
  }

  /** Helper function for instructions with the format `fabs vd, vn`.
   */
  template <typename T>
  static std::array<T, 256> fabs_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    std::array<T, 256> out = {0};
    out[0] = std::fabs(n);
    return out;
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng