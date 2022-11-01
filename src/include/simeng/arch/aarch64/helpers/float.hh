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
  static RegisterValue fabd_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fabs(n - m), 256};
  }

  /** Helper function for instructions with the format `fabs rd, rn`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fabs_2ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    return {std::fabs(n), 256};
  }

  /** Helper function for instructions with the format `fccmp rn, rm, #nzcv,
   * cc`.
   * T represents the type of operands (e.g. for sn T = float).
   * Returns single value of type uint8_t. */
  template <typename T>
  static uint8_t fccmp(
      std::vector<RegisterValue>& operands,
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
  static uint8_t fcmp(std::vector<RegisterValue>& operands, bool useImm) {
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
  static RegisterValue fmaxnm_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fmax(n, m), 256};
  }

  /** Helper function for instructions with the format `fmaxnm rd, rn, rm`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fminnm_3ops(std::vector<RegisterValue>& operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return {std::fmin(n, m), 256};
  }

  /** Helper function for NEON instructions with the format `fnmsub rd, rn, rm,
   * ra`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fnmsub_4ops(std::vector<RegisterValue>& operands) {
    T n = operands[0].get<T>();
    T m = operands[1].get<T>();
    T a = operands[2].get<T>();
    return {std::fma(n, m, -a), 256};
  }

  /** Helper function for NEON instructions with the format `fnmadd rd, rn, rm,
   * ra`.
   * T represents the type of operands (e.g. for sd T = float).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue fnmadd_4ops(std::vector<RegisterValue>& operands) {
    T n = operands[0].get<T>();
    T m = operands[1].get<T>();
    T a = operands[2].get<T>();
    return {std::fma(-n, m, -a), 256};
  }

  /** Helper function for NEON instructions with the format `frintp rd, rn`.
   * T represents the type of operands (e.g. for dd T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue frintpScalar_2ops(std::vector<RegisterValue>& operands) {
    T n = operands[0].get<T>();

    // Merge always = false due to assumption that FPCR.nep bit = 0
    // (In SimEng the value of this register is not manually set)
    T out = 0;
    // Input of Infinity or 0 gives output of the same sign
    if (n == 0.0 || n == -0.0 || n == INFINITY || n == -INFINITY)
      out = n;
    else
      out = std::ceil(n);

    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `scvtf rd,
   *  <w,x>n`, #fbits.
   * D represents the destination vector register type (e.g. for dd, D =
   * double).
   * N represents the source vector register type (e.g. for wn, N = int32_t).
   * Returns correctly formated RegisterValue. */
  template <typename D, typename N>
  static RegisterValue scvtf_FixedPoint(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    N n = operands[0].get<N>();
    const uint8_t fbits = metadata.operands[2].imm;

    D out = static_cast<D>(n) / std::pow(2, fbits);

    return {out, 256};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng