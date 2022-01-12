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
  /** Helper function for instructions with the format `add rd, rn, rm`. Returns
   * Single value. */
  template <typename T>
  static T add_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n + m);
  }

  /** Helper function for instructions with the format `add rd, rn, #imm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m = shiftValue(static_cast<T>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
    return ExecHelpFunc::addWithCarry(n, m, 0);
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    return ExecHelpFunc::addWithCarry(n, m, 0);
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, extend
   * {#amount}}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addExtend_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m = ExecHelpFunc::extendValue(operands[1].get<T>(),
                                          metadata.operands[2].ext,
                                          metadata.operands[2].shift.value);
    return ExecHelpFunc::addWithCarry(n, m, 0);
  }

  /** Helper function for instructions with the format `adc rd, rn, rm`. Returns
   * tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addCarry_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const uint8_t carry = operands[0].get<uint8_t>() & 0b0010;
    const T n = operands[1].get<T>();
    const T m = operands[2].get<T>();
    return ExecHelpFunc::addWithCarry(n, m, carry);
  }

  /** Helper function for instructions with the format `madd rd, rn, rm, ra`.
   * Returns single value. */
  template <typename T>
  static T madd_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a + (n * m));
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, #imm`. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m = ~shiftValue(static_cast<T>(metadata.operands[2].imm),
                            metadata.operands[2].shift.type,
                            metadata.operands[2].shift.value);
    return ExecHelpFunc::addWithCarry(n, m, true);
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, rm{,
   * shift #amount}`. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m =
        ~shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                    metadata.operands[2].shift.value);
    return ExecHelpFunc::addWithCarry(n, m, true);
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, rm{,
   * extend #amount}`. */
  template <typename T>
  static std::tuple<T, uint8_t> subExtend_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    const T n = operands[0].get<T>();
    const T m = static_cast<T>(~ExecHelpFunc::extendValue(
        operands[1].get<T>(), metadata.operands[2].ext,
        metadata.operands[2].shift.value));
    return ExecHelpFunc::addWithCarry(n, m, true);
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng