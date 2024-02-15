#pragma once

#include <limits>

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `fabd rd, rn, rm`.
 * T represents the type of operands (e.g. for sd T = float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue fabd_3ops(srcOperandContainer<RegisterValue>& operands) {
  const T n = operands[0].get<T>();
  const T m = operands[1].get<T>();
  return {std::fabs(n - m), 256};
}

/** Helper function for instructions with the format `fabs rd, rn`.
 * T represents the type of operands (e.g. for sd T = float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue fabs_2ops(srcOperandContainer<RegisterValue>& operands) {
  const T n = operands[0].get<T>();
  return {std::fabs(n), 256};
}

/** Helper function for instructions with the format `fccmp rn, rm, #nzcv,
 * cc`.
 * T represents the type of operands (e.g. for sn T = float).
 * Returns single value of type uint8_t. */
template <typename T>
uint8_t fccmp(srcOperandContainer<RegisterValue>& operands,
              const simeng::arch::aarch64::InstructionMetadata& metadata) {
  if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
    T a = operands[1].get<T>();
    T b = operands[2].get<T>();
    if (std::isnan(a) || std::isnan(b)) {
      // TODO: Raise exception if NaNs are signalling or fcmpe
      return nzcv(false, false, true, true);
    } else if (a == b) {
      return nzcv(false, true, true, false);
    } else if (a < b) {
      return nzcv(true, false, false, false);
    } else {
      return nzcv(false, false, true, false);
    }
  }
  return static_cast<uint8_t>(metadata.operands[2].imm);
}

/** Helper function for instructions with the format `fcmp rn, <rm, #imm>`.
 * T represents the type of operands (e.g. for sn T = float).
 * Returns single value of type uint8_t. */
template <typename T>
uint8_t fcmp(srcOperandContainer<RegisterValue>& operands, bool useImm) {
  T a = operands[0].get<T>();
  // Dont need to fetch imm as will always be 0.0
  T b = useImm ? 0 : operands[1].get<T>();
  if (std::isnan(a) || std::isnan(b)) {
    // TODO: Raise exception if NaNs are signalling or fcmpe
    return nzcv(false, false, true, true);
  } else if (a == b) {
    return nzcv(false, true, true, false);
  } else if (a < b) {
    return nzcv(true, false, false, false);
  }
  return nzcv(false, false, true, false);
}

/** Helper function for instructions with the format `fmaxnm rd, rn, rm`.
 * T represents the type of operands (e.g. for sd T = float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue fmaxnm_3ops(srcOperandContainer<RegisterValue>& operands) {
  const T n = operands[0].get<T>();
  const T m = operands[1].get<T>();
  return {std::fmax(n, m), 256};
}

/** Helper function for instructions with the format `fmaxnm rd, rn, rm`.
 * T represents the type of operands (e.g. for sd T = float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue fminnm_3ops(srcOperandContainer<RegisterValue>& operands) {
  const T n = operands[0].get<T>();
  const T m = operands[1].get<T>();
  return {std::fmin(n, m), 256};
}

/** Helper function for NEON instructions with the format `fnmsub rd, rn, rm,
 * ra`.
 * T represents the type of operands (e.g. for sd T = float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue fnmsub_4ops(srcOperandContainer<RegisterValue>& operands) {
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
RegisterValue fnmadd_4ops(srcOperandContainer<RegisterValue>& operands) {
  T n = operands[0].get<T>();
  T m = operands[1].get<T>();
  T a = operands[2].get<T>();
  return {std::fma(-n, m, -a), 256};
}

/** Helper function for NEON instructions with the format `frintp rd, rn`.
 * T represents the type of operands (e.g. for dd T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue frintpScalar_2ops(srcOperandContainer<RegisterValue>& operands) {
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
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N>
RegisterValue scvtf_FixedPoint(
    srcOperandContainer<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  N n = operands[0].get<N>();
  const uint8_t fbits = metadata.operands[2].imm;

  D out = static_cast<D>(n) / std::pow(2, fbits);

  return {out, 256};
}

/** Helper function for NEON instructions with the format fcvtzu rd, rn.
 * D represents the destination register type (e.g. for Xd, D = uint64_t).
 * N represents the source register type (e.g. for Sd, N = float).
 * Returns single value of type D. */
template <typename D, typename N>
D fcvtzu_integer(srcOperandContainer<RegisterValue>& operands) {
  N input = operands[0].get<N>();
  D result = static_cast<D>(0);

  // Check for nan and less than 0
  if (!std::isnan(input) && (input > static_cast<N>(0))) {
    if (std::isinf(input)) {
      // Account for Infinity
      result = std::numeric_limits<D>::max();
    } else if (input > std::numeric_limits<D>::max()) {
      // Account for the source value being larger than the
      // destination register can support
      result = std::numeric_limits<D>::max();
    } else {
      result = static_cast<D>(std::trunc(input));
    }
  }

  return result;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng