#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class divideHelp {
 public:
  /** Helper function for instructions with the format `div rd, rn, rm`.
   * T represents the type of operands (e.g. for xd, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T div_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    if (m == 0) return 0;
    return (n / m);
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng