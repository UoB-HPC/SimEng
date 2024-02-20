#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `madd rd, rn, rm, ra`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T madd_4ops(srcValContainer& sourceValues) {
  const T n = sourceValues[0].get<T>();
  const T m = sourceValues[1].get<T>();
  const T a = sourceValues[2].get<T>();
  return (a + (n * m));
}

/** Helper function for instructions with the format `maddl xd, wn, wm, xa`.
 * D represents the type of the destination register (either int64_t or
 * uint64_t).
 * N represents the type of the first source register (either
 * int32_t or uint32_t).
 * Returns single value of type D. */
template <typename D, typename N>
D maddl_4ops(srcValContainer& sourceValues) {
  const D n = static_cast<D>(sourceValues[0].get<N>());
  const D m = static_cast<D>(sourceValues[1].get<N>());
  const D a = sourceValues[2].get<D>();
  return (a + (n * m));
}

/** Helper function for instructions with the format `mul rd, rn, rm`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T mul_3ops(srcValContainer& sourceValues) {
  const T n = sourceValues[0].get<T>();
  const T m = sourceValues[1].get<T>();
  return (n * m);
}

/** Helper function for instructions with the format `msub rd, rn, rm, ra`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T msub_4ops(srcValContainer& sourceValues) {
  const T n = sourceValues[0].get<T>();
  const T m = sourceValues[1].get<T>();
  const T a = sourceValues[2].get<T>();
  return (a - (n * m));
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng