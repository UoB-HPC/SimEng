#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class multiplyHelp {
 public:
  /** Helper function for instructions with the format `madd rd, rn, rm, ra`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T madd_4ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a + (n * m));
  }

  /** Helper function for instructions with the format `maddl xd, wn, wm, xa`.
   * D represents the type of the destination register (either int64_t or
   * uint64_t).
   * N represents the type of the first source register (either
   * int32_t or uint32_t).
   * Returns single value of type D. */
  template <typename D, typename N>
  static D maddl_4ops(std::vector<RegisterValue>& operands) {
    const D n = static_cast<D>(operands[0].get<N>());
    const D m = static_cast<D>(operands[1].get<N>());
    const D a = operands[2].get<D>();
    return (a + (n * m));
  }

  /** Helper function for instructions with the format `mul rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T mul_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n * m);
  }

  /** Helper function for instructions with the format `msub rd, rn, rm, ra`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T msub_4ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a - (n * m));
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng