#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `div rd, rn, rm`.
 * T represents the type of sourceValues (e.g. for xd, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T div_3ops(srcValContainer& sourceValues) {
  const T n = sourceValues[0].get<T>();
  const T m = sourceValues[1].get<T>();
  if (m == 0) return 0;
  return (n / m);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng