#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class logicalHelp {
 public:
  /** Helper function for instructions with the format `asrv rd, rn, rm`.
   * T represents the output type (i.e. for wd, T = int32_t).
   * Returns single value of type T. */
  template <typename T>
  static T asrv_3gpr(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<typename std::make_unsigned<T>::type>();
    return n >> (m % (sizeof(T) * 8));
  }

  /** Helper function for instructions with the format `bic rd, rn, rm{, shift
   * #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> bicShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
   * #imm`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> logicOp_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
   * rm{, shift #amount}`. Returns tuple of [resulting value, nzcv]. */
  template <typename T>
  static std::tuple<T, uint8_t> logicOpShift_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng