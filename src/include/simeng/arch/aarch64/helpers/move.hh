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
  /** Helper function for instructions with the format `movz {w,x}d, #imm`.
   */
  template <typename T>
  static T movz_imm(
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    uint8_t shift = metadata.operands[1].shift.value;
    T value = static_cast<uint64_t>(metadata.operands[1].imm) << shift;
    return value;
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng