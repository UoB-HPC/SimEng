#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class arithmeticHelp {
 public:
  /** Helper function for instructions with the format `add rd, rn, rm`. Returns
   * Single value. */
  template <typename T>
  static T add_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n + m);
  }

  /** Helper function for instructions with the format `add rd, rn, #imm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = shiftValue(static_cast<T>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, extend
   * {#amount}}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addExtend_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        AuxFunc::extendValue(operands[1].get<T>(), metadata.operands[2].ext,
                             metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `adc rd, rn, rm`. Returns
   * tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addCarry_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const uint8_t carry = operands[0].get<uint8_t>() & 0b0010;
    const T n = operands[1].get<T>();
    const T m = operands[2].get<T>();
    return AuxFunc::addWithCarry(n, m, carry);
  }

  /** Helper function for instructions with the format `clz rd, rn`. */
  template <typename T>
  static T clz_reg(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    T x = operands[0].get<T>();
    uint8_t i;
    for (i = 0; i < (sizeof(T) * 8); i++) {
      // Left-shift x until it's negative or we run out of bits
      if (x < 0) {
        break;
      }
      x <<= 1;
    }
    return i;
  }

  /** Helper function for instructions with the format `madd rd, rn, rm, ra`.
   * Returns single value. */
  template <typename T>
  static T madd_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    const T a = operands[2].get<T>();
    return (a + (n * m));
  }

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

  /** Helper function for instructions with the format `mov<n,z> <w,x>d, #imm{,
   * lsl #shift}`.
   */
  template <typename T>
  static uint64_t movnShift_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      std::function<T(uint64_t)> func) {
    uint8_t shift = metadata.operands[1].shift.value;
    T value = func(static_cast<uint64_t>(metadata.operands[1].imm) << shift);
    return static_cast<uint64_t>(value);
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, #imm`. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = shiftValue(static_cast<T>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, ~m, true);
    return {(n - m), 0};
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, rm{,
   * shift #amount}`. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, ~m, true);
    return {(n - m), 0};
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, rm{,
   * extend #amount}`. */
  template <typename T>
  static std::tuple<T, uint8_t> subExtend_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = static_cast<T>(
        AuxFunc::extendValue(operands[1].get<T>(), metadata.operands[2].ext,
                             metadata.operands[2].shift.value));
    if (calcNZCV) return AuxFunc::addWithCarry(n, ~m, true);
    return {(n - m), 0};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng