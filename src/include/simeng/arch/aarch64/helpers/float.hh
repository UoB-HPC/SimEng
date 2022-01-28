#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class floatHelp {
 public:
  /** Helper function for instructions with the format `fabd rd, rn, rm`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fabd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fabs(n - m), 256};
  }

  /** Helper function for instructions with the format `fabs rd, rn`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fabs_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    return {std::fabs(n), 256};
  }

  /** Helper function for instructions with the format `fccmp rn, rm, #nzcv,
   * cc`.
   * T represents the type of operands (e.g. for sn T = float).
   * Returns single value of type uint8_t. */
  template <typename T>
  static uint8_t fccmp(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
      T a = operands[1].get<T>();
      T b = operands[2].get<T>();
      if (std::isnan(a) || std::isnan(b)) {
        // TODO: Raise exception if NaNs are signalling or fcmpe
        return AuxFunc::nzcv(false, false, true, true);
      } else if (a == b) {
        return AuxFunc::nzcv(false, true, true, false);
      } else if (a < b) {
        return AuxFunc::nzcv(true, false, false, false);
      } else {
        return AuxFunc::nzcv(false, false, true, false);
      }
    }
    return static_cast<uint8_t>(metadata.operands[2].imm);
  }

  /** Helper function for instructions with the format `fcmp rn, <rm, #imm>`.
   * T represents the type of operands (e.g. for sn T = float).
   * Returns single value of type uint8_t. */
  template <typename T>
  static uint8_t fcmp(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      bool useImm) {
    T a = operands[0].get<T>();
    // Dont need to fetch imm as will always be 0.0
    T b = useImm ? 0 : operands[1].get<T>();
    if (std::isnan(a) || std::isnan(b)) {
      // TODO: Raise exception if NaNs are signalling or fcmpe
      return AuxFunc::nzcv(false, false, true, true);
    } else if (a == b) {
      return AuxFunc::nzcv(false, true, true, false);
    } else if (a < b) {
      return AuxFunc::nzcv(true, false, false, false);
    }
    return AuxFunc::nzcv(false, false, true, false);
  }

  /** Helper function for instructions with the format `fmaxnm rd, rn, rm`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fmaxnm_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fmax(n, m), 256};
  }

  /** Helper function for instructions with the format `fmaxnm rd, rn, rm`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fminnm_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fmin(n, m), 256};
  }

  /** Helper function for NEON instructions with the format `fnmsub rd, rn, rm,
   * ra`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fnmsub_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    T n = operands[0].get<T>();
    T m = operands[1].get<T>();
    T a = operands[2].get<T>();
    return {std::fma(n, m, -a), 256};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng