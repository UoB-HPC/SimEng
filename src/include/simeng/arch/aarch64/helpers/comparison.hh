#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `orr rd, rn, rm {shift
 * #amount}`.
 * T represents the type of operands (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T orrShift_3ops(srcOperandContainer<RegisterValue>& operands,
                const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T n = operands[0].get<T>();
  const T m = shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                         metadata.operands[2].shift.value);
  return (n | m);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng