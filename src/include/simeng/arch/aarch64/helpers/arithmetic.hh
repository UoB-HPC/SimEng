#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "ExecuteHelperFunctions.hh"
#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class arithmeticHelp {
 public:
  /** Helper function for instructions with the format `add rd, rn, rm`. */
  template <typename T>
  static T add_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n + m);
  }

  /** Helper function for instructions with the format `add rd, rn, rm {shift
   * #amount}`. */
  template <typename T>
  static T addShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    return (n + m);
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng