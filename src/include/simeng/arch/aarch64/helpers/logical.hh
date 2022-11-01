#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class logicalHelp {
 public:
  /** Helper function for instructions with the format `asrv rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = int64_t).
   * Returns single value of type T. */
  template <typename T>
  static T asrv_3gpr(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<typename std::make_unsigned<T>::type>();
    return n >> (m % (sizeof(T) * 8));
  }

  /** Helper function for instructions with the format `bic rd, rn, rm{, shift
   * #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> bicShift_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      bool calcNZCV) {
    const T x = operands[0].get<T>();
    const T y =
        ~shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                    metadata.operands[2].shift.value);
    T result = x & y;
    bool n = sizeof(T) == 8 ? (static_cast<int64_t>(result) < 0)
                            : (static_cast<int32_t>(result) < 0);
    bool z = (result == 0);
    uint8_t nzcv = calcNZCV ? AuxFunc::nzcv(n, z, false, false) : 0;
    return {result, nzcv};
  }

  /** Helper function for instructions with the format `<and, eor, ...> rd, rn,
   * #imm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> logicOp_imm(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata, bool calcNZCV,
      std::function<T(T, T)> func) {
    const T n = operands[0].get<T>();
    const T m = static_cast<T>(metadata.operands[2].imm);
    T result = func(n, m);
    uint8_t nzcv = calcNZCV ? AuxFunc::nzcv(result >> ((sizeof(T) * 8) - 1),
                                            result == 0, false, false)
                            : 0;
    return {result, nzcv};
  }

  /** Helper function for instructions with the format `<and, eor, ...> rd, rn,
   * rm{, shift #amount}`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> logicOpShift_3ops(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata, bool calcNZCV,
      std::function<T(T, T)> func) {
    const T n = operands[0].get<T>();
    const T m =
        shiftValue(operands[1].get<T>(), metadata.operands[2].shift.type,
                   metadata.operands[2].shift.value);
    T result = func(n, m);
    uint8_t nzcv = calcNZCV ? AuxFunc::nzcv(result >> ((sizeof(T) * 8) - 1),
                                            result == 0, false, false)
                            : 0;
    return {result, nzcv};
  }

  /** Helper function for instructions with the format `ls<l,r>v rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t logicalShiftLR_3ops(std::vector<RegisterValue>& operands,
                                      bool isLSL) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>() & ((sizeof(T) * 8) - 1);
    uint64_t result = static_cast<uint64_t>(isLSL ? n << m : n >> m);
    return result;
  }

  /** Helper function for instructions with the format `rorv rd, rn, rm`.
   * T represents the type of operands (e.g. for xn, T = uint64_t).
   * Returns single value of type T. */
  template <typename T>
  static T rorv_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();

    const uint16_t data_size = sizeof(T) * 8;
    T remainder = m % data_size;

    // Check if any rotation done at all
    if (remainder == 0) return n;
    return (n >> remainder) + (n << (data_size - remainder));
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng