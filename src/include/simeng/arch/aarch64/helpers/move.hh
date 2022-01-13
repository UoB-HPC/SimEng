#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "ExecuteHelperFunctions.hh"
#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class moveHelp {
 public:
  /** Helper function for instructions with the format `movk <w,x>d, #imm`.
   */
  template <typename T>
  static T movkShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    // Clear 16-bit region offset by `shift` and replace with immediate
    uint8_t shift = metadata.operands[1].shift.value;
    T mask = ~(static_cast<T>(0xFFFF) << shift);
    T value =
        (operands[0].get<T>() & mask) | (metadata.operands[1].imm << shift);
    return value;
  }

  /** Helper function for instructions with the format `movn <w,x>d, #imm{, lsl
   * #shift}`.
   */
  template <typename T>
  static uint64_t movnShift_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      std::function<T(uint64_t)> func) {
    uint8_t shift = metadata.operands[1].shift.value;
    T value = func(static_cast<uint64_t>(metadata.operands[1].imm) << shift);
    return static_cast<uint64_t>(value);
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng