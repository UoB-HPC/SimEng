#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class arithmeticHelp {
 public:
  /** Helper function for instructions with the format `add rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T add_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n + m);
  }

  /** Helper function for instructions with the format `adc rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addCarry_3ops(
      std::vector<RegisterValue>& operands) {
    const uint8_t carry = operands[0].get<uint8_t>() & 0b0010;
    const T n = operands[1].get<T>();
    const T m = operands[2].get<T>();
    return AuxFunc::addWithCarry(n, m, carry);
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, extend
   * {#amount}}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addExtend_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        AuxFunc::extendValue(operands[1].get<T>(), metadata.operands[2].ext,
                             metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `add rd, rn, rm{, shift
   * #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `add rd, rn, #imm{, shift
   * #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> addShift_imm(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = shiftValue(static_cast<T>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, m, 0);
    return {(n + m), 0};
  }

  /** Helper function for instructions with the format `clz rd, rn`.
   * T represents the type of operands (e.g. for xn, T = int64_t).
   * Returns single value of type T. */
  template <typename T>
  static T clz_reg(std::vector<RegisterValue>& operands) {
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

  /** Helper function for instructions with the format `movk <w,x>d, #imm`.
   * T represents the type of operands (e.g. for xd, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T movkShift_imm(
      std::vector<RegisterValue>& operands,
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
   * T represents the type of operands (e.g. for xd, T = uint64_t).
   * Returns single value og type uint64_t. */
  template <typename T>
  static uint64_t movnShift_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      std::function<T(uint64_t)> func) {
    uint8_t shift = metadata.operands[1].shift.value;
    T value = func(static_cast<uint64_t>(metadata.operands[1].imm) << shift);
    return static_cast<uint64_t>(value);
  }

  /** Helper function for instructions with the format `msubl xd, wn, wm, xa`.
   * D represents the type of the destination register (either int64_t or
   * uint64_t).
   * N represents the type of the first source register (either
   * int32_t or uint32_t).
   * Returns single value of type D. */
  template <typename D, typename N>
  static D msubl_4ops(std::vector<RegisterValue>& operands) {
    const N n = operands[0].get<N>();
    const N m = operands[1].get<N>();
    const D a = operands[2].get<D>();
    return (a - (n * m));
  }

  /** Helper function for instructions with the format `sbc rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T sbc(std::vector<RegisterValue>& operands) {
    auto nzcv = operands[0].get<uint8_t>();
    const T x = operands[1].get<T>();
    const T y = operands[2].get<T>();
    T result;
    std::tie(result, std::ignore) =
        AuxFunc::addWithCarry(x, ~y, (nzcv >> 1) & 1);
    return result;
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, rm{,
   * extend #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> subExtend_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = static_cast<T>(
        AuxFunc::extendValue(operands[1].get<T>(), metadata.operands[2].ext,
                             metadata.operands[2].shift.value));
    if (calcNZCV) return AuxFunc::addWithCarry(n, ~m, true);
    return {(n - m), 0};
  }

  /** Helper function for instructions with the format `sub{s} rd, rn, #imm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_imm(
      std::vector<RegisterValue>& operands,
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
   * shift #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> subShift_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    if (calcNZCV) return AuxFunc::addWithCarry(n, ~m, true);
    return {(n - m), 0};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng