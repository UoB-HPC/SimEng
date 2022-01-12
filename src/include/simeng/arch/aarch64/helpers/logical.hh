#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "ExecuteHelperFunctions.hh"
#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class logicalHelp {
 public:
  /** Helper function for instructions with the format `and rd, rn, #imm`.
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> and_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m = static_cast<T>(metadata.operands[2].imm);
    T result = n & m;
    return {result, ExecHelpFunc::nzcv(result >> ((sizeof(T) * 8) - 1),
                                       result == 0, false, false)};
  }

  /** Helper function for instructions with the format `and rd, rn, rm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> andShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    T result = n & m;
    return {result, ExecHelpFunc::nzcv(result >> ((sizeof(T) * 8) - 1),
                                       result == 0, false, false)};
  }

  /** Helper function for instructions with the format `and rd, rn, rm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> bicShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T x = operands[0].get<T>();
    const T y =
        ~shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                    metadata.operands[2].shift.value);
    T result = x & y;
    bool n = sizeof(T) == 8 ? (static_cast<int64_t>(result) < 0)
                            : (static_cast<int32_t>(result) < 0);
    bool z = (result == 0);
    return {result, ExecHelpFunc::nzcv(n, z, false, false)};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng