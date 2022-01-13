#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class divideHelp {
 public:
  /** Helper function for instructions with the format `div rd, rn, rm`. */
  template <typename T>
  static T div_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    if (m == 0) return 0;
    return (n / m);
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng