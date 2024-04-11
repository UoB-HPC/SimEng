#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for NEON instructions with the format `add vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted Register Value. */
template <typename T, int I>
RegisterValue vecAdd_3ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = static_cast<T>(n[i] + m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `addp vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted Register Value. */
template <typename T, int I>
RegisterValue vecAddp_3ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  uint8_t offset = I / 2;
  for (int i = 0; i < I; i++) {
    if (i < offset) {
      out[i] = static_cast<T>(n[i * 2] + n[(i * 2) + 1]);
    } else {
      out[i] = static_cast<T>(m[(i - offset) * 2] + m[((i - offset) * 2) + 1]);
    }
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `bic vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted Register Value. */
template <typename T, int I>
RegisterValue vecBic_3ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = n[i] & ~m[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `bic vd, #imm{, lsl
 * #shift}`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted Register Value. */
template <typename T, int I>
RegisterValue vecBicShift_imm(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* d = sourceValues[0].getAsVector<T>();
  T imm = ~shiftValue(static_cast<T>(metadata.operands[1].imm),
                      metadata.operands[1].shift.type,
                      metadata.operands[1].shift.value);
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i] & imm;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `bi<f,t> vd, vn,
 * vm`.
 * I represents the number of elements in the output array to be updated
 * (e.g. for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <int I>
RegisterValue vecBitwiseInsert(srcValContainer& sourceValues, bool isBif) {
  const uint64_t* d = sourceValues[0].getAsVector<uint64_t>();
  const uint64_t* n = sourceValues[1].getAsVector<uint64_t>();
  const uint64_t* m = sourceValues[2].getAsVector<uint64_t>();
  uint64_t out[2] = {0};
  for (int i = 0; i < (I / 8); i++) {
    out[i] =
        isBif ? (d[i] & m[i]) | (n[i] & ~m[i]) : (d[i] & ~m[i]) | (n[i] & m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `bsl vd, vn,
 * vm`.
 * I represents the number of elements in the output array to be updated
 * (e.g. for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <int I>
RegisterValue vecBsl(srcValContainer& sourceValues) {
  const uint64_t* d = sourceValues[0].getAsVector<uint64_t>();
  const uint64_t* n = sourceValues[1].getAsVector<uint64_t>();
  const uint64_t* m = sourceValues[2].getAsVector<uint64_t>();
  uint64_t out[2] = {0};
  for (int i = 0; i < (I / 8); i++) {
    out[i] = (d[i] & n[i]) | (~d[i] & m[i]);
  }
  return {out, 256};
}

/** Helper function for instructions with the format `cm<eq, ge, gt, hi, hs,
 *le, lt> vd, vn, <vm, #0>`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecCompare(srcValContainer& sourceValues, bool cmpToZero,
                         std::function<bool(T, T)> func) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m;
  if (!cmpToZero) m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = func(n[i], cmpToZero ? static_cast<T>(0) : m[i])
                 ? static_cast<T>(-1)
                 : 0;
  }
  return {out, 256};
}

/** Helper function for instructions with the format `cnt vd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecCountPerByte(srcValContainer& sourceValues) {
  const uint8_t* n = sourceValues[0].getAsVector<uint8_t>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    for (size_t j = 0; j < (sizeof(T) * 8); j++) {
      // Move queried bit to LSB and extract via an AND operator
      out[i] += ((n[i] >> j) & 1);
    }
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `dup <rd, vd>,
 * <vn[index], rn>`.
 * T represents the type of sourceValues (e.g. for vd.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecDup_gprOrIndex(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata, bool useGpr) {
  int index = useGpr ? 0 : metadata.operands[1].vector_index;
  T element = useGpr ? sourceValues[0].get<T>()
                     : sourceValues[0].getAsVector<T>()[index];
  T out[16 / sizeof(T)] = {0};
  std::fill_n(std::begin(out), I, element);
  return {out, 256};
}

/** Helper function for NEON instructions with the format `ext vd,
 *  vn, vm, #index`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecExtVecs_index(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  const uint64_t index = static_cast<uint64_t>(metadata.operands[3].imm);
  T out[16 / sizeof(T)] = {0};

  for (uint64_t i = index; i < I; i++) {
    out[i - index] = n[i];
  }
  for (uint64_t i = 0; i < index; i++) {
    out[I - index + i] = m[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fabd vd.T, vn.T,
 * vm.T`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFabd(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = std::fabs(n[i] - m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fabs vd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFabs_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = std::fabs(n[i]);
  }
  return {out, 256};
}

/** Helper function for instructions with the format `fcm<eq, ge, gt, hi, hs,
 *le, lt> vd, vn, <vm, #0>`.
 * T represents operand type (e.g. vd.2d is double).
 * C represents comparison type (e.g. for T=float, comparison type is
 * uint32_t).
 * I represents the number of elements in the output array to be
 * updated (e.g. for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, typename C, int I>
RegisterValue vecFCompare(srcValContainer& sourceValues, bool cmpToZero,
                          std::function<bool(T, T)> func) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m;
  if (!cmpToZero) m = sourceValues[1].getAsVector<T>();
  C out[16 / sizeof(C)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = func(n[i], cmpToZero ? static_cast<T>(0) : m[i])
                 ? static_cast<C>(-1)
                 : 0;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fcvtl{2} vd, vn`.
 * D represents the dest. vector register type (e.g. vd.2d would be double).
 * N represents the source vector register type (e.g. vd.4s would be float).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecFcvtl(srcValContainer& sourceValues, bool isFcvtl2) {
  const N* n = sourceValues[0].getAsVector<N>();
  D out[16 / sizeof(D)] = {0};
  for (int i = (isFcvtl2 ? I : 0); i < (isFcvtl2 ? (I * 2) : I); i++) {
    out[isFcvtl2 ? (i - I) : i] = static_cast<D>(n[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fcvtn{2} vd, vn`.
 * D represents the dest. vector register type (e.g. vd.2s would be float).
 * N represents the source vector register type (e.g. vd.2d would be double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecFcvtn(srcValContainer& sourceValues, bool isFcvtn2) {
  const N* n = sourceValues[0].getAsVector<N>();
  D out[16 / sizeof(D)] = {0};
  for (int i = (isFcvtn2 ? (I / 2) : 0); i < I; i++) {
    out[i] = static_cast<D>(n[isFcvtn2 ? (i - (I / 2)) : i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fcvtzs vd, vn`.
 * D represents the dest. vector register type (e.g. vd.2s would be float).
 * N represents the source vector register type (e.g. vd.2d would be double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecFcvtzs(srcValContainer& sourceValues) {
  const N* n = sourceValues[0].getAsVector<N>();
  D out[16 / sizeof(D)] = {0};
  // TODO: Handle NaNs, denorms, and saturation
  for (int i = 0; i < I; i++) {
    out[i] = static_cast<D>(std::trunc(n[i]));
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fmla vd,
 *  vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFmla_3vecs(srcValContainer& sourceValues) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T* n = sourceValues[1].getAsVector<T>();
  const T* m = sourceValues[2].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i] + n[i] * m[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fdiv vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
std::enable_if_t<std::is_floating_point_v<T>, RegisterValue> vecFDiv(
    srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    if (m[i] == 0)
      out[i] = sizeof(T) == 8 ? std::nan("") : std::nanf("");
    else
      out[i] = n[i] / m[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fmla vd,
 *  vn, vm[index]`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFmlaIndexed_3vecs(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T* n = sourceValues[1].getAsVector<T>();
  int index = metadata.operands[2].vector_index;
  const T m = sourceValues[2].getAsVector<T>()[index];
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i] + n[i] * m;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fmls vd,
 *  vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFmls_3vecs(srcValContainer& sourceValues) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T* n = sourceValues[1].getAsVector<T>();
  const T* m = sourceValues[2].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i] - (n[i] * m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fmls vd,
 *  vn, vm[index]`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFmlsIndexed_3vecs(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T* n = sourceValues[1].getAsVector<T>();
  int index = metadata.operands[2].vector_index;
  const T m = sourceValues[2].getAsVector<T>()[index];
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i] - n[i] * m;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fmul rd,
 *  rn, vm[index]`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFmulIndexed_vecs(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  int index = metadata.operands[2].vector_index;
  const T* n = sourceValues[0].getAsVector<T>();
  const T m = sourceValues[1].getAsVector<T>()[index];
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = n[i] * m;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fneg vd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFneg_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = -n[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `fsqrt vd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFsqrt_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = ::sqrt(n[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `frsqrte vd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFrsqrte_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = 1.0f / sqrtf(n[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `frsqrts vd, vn,
 * vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = double).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecFrsqrts_3ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = (3.0f - n[i] * m[i]) / 2.0f;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `ins vd[index],
 *  vn[index]`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecIns_2Index(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T* n = sourceValues[1].getAsVector<T>();

  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = d[i];
  }
  out[metadata.operands[0].vector_index] = n[metadata.operands[1].vector_index];
  return {out, 256};
}

/** Helper function for NEON instructions with the format `ins vd[index],
 *  rn`.
 * T represents the vector register type (e.g. vd.16b would be uint8_t).
 * R represents the type of the GPR (e.g. wn would be uint32_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, typename R, int I>
RegisterValue vecInsIndex_gpr(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* d = sourceValues[0].getAsVector<T>();
  const T n = sourceValues[1].get<R>();
  T out[16 / sizeof(T)] = {0};

  for (int i = 0; i < I; i++) {
    out[i] = d[i];
  }
  out[metadata.operands[0].vector_index] = n;
  return {out, 256};
}

/** Helper function for NEON instructions with the format `<NOT, ...> vd,
 *  vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecLogicOp_2vecs(srcValContainer& sourceValues,
                               std::function<T(T)> func) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = func(n[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `<AND, EOR, ...> vd,
 *  vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecLogicOp_3vecs(srcValContainer& sourceValues,
                               std::function<T(T, T)> func) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = func(n[i], m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `umaxp vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecUMaxP(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[I];
  for (int i = 0; i < I; i++) {
    out[i] = std::max(n[i], m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `uminp vd, vn, vm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecUMinP(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[I];
  for (int i = 0; i < I; i++) {
    out[i] = std::min(n[i], m[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `maxnmp rd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecMaxnmp_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  bool isFP = std::is_floating_point<T>::value;

  T out = n[0];
  for (int i = 1; i < I; i++) {
    out = isFP ? std::fmax(n[i], out) : std::max(n[i], out);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `sminv sd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecMinv_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  bool isFP = std::is_floating_point<T>::value;

  T out = n[0];
  for (int i = 1; i < I; i++) {
    out = isFP ? std::fmin(n[i], out) : std::min(n[i], out);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `movi vd, #imm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecMovi_imm(
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  bool isFP = std::is_floating_point<T>::value;
  const T imm =
      isFP ? metadata.operands[1].fp : static_cast<T>(metadata.operands[1].imm);
  T out[16 / sizeof(T)] = {0};
  std::fill_n(std::begin(out), I, imm);
  return {out, 256};
}

/** Helper function for NEON instructions with the format `movi vd, #imm{, lsl
 * #shift}`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecMoviShift_imm(
    const simeng::arch::aarch64::InstructionMetadata& metadata, bool negate) {
  const T bits = shiftValue(static_cast<T>(metadata.operands[1].imm),
                            metadata.operands[1].shift.type,
                            metadata.operands[1].shift.value);
  T out[16 / sizeof(T)] = {0};
  std::fill_n(std::begin(out), I, negate ? ~bits : bits);
  return {out, 256};
}

/** Helper function for NEON instructions with the format `scvtf vd,
 *  vn`.
 * D represents the destination vector register type (e.g. for vd.2d, D =
 * double).
 * N represents the source vector register type (e.g. for vn.2s N = int32_t).
 * I represents the number of elements in the output array to be
 * updated (e.g. for vd.8b I = 8).
 * Returns correctly formated RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecScvtf_2vecs(srcValContainer& sourceValues,
                             std::function<D(N)> func) {
  const N* n = sourceValues[0].getAsVector<N>();
  D out[16 / sizeof(D)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = static_cast<D>(n[i]);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `shl vd, vn, #imm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecShlShift_vecImm(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* n = sourceValues[0].getAsVector<T>();
  int64_t shift = metadata.operands[2].imm;
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = static_cast<T>(n[i] << shift);
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `shll{2} vd, vn,
 * #imm`.
 * D represents the destination register type (e.g. for vd.2d D = int64_t).
 * N represents the source register type (e.g. for vd.4s D = int32_t).
 * I represents the number of elements in the output array to be
 * updated (e.g. for vd.8h the I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecShllShift_vecImm(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata, bool isShll2) {
  const N* n = sourceValues[0].getAsVector<N>();
  uint64_t shift = metadata.operands[2].imm;
  D out[16 / sizeof(D)] = {0};
  int index = isShll2 ? I : 0;
  for (int i = 0; i < I; i++) {
    out[i] = n[index] << shift;
    index++;
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `shrn vd, vn, #imm`.
 * Ta represents the type of source operand (e.g. for vn.2d, Ta = uint64_t).
 * Tb represents the type of destination operand (e.g. for vd.2s, Tb =
 * uint32_t).
 * I represents the number of elements in the output array to be
 * updated (e.g. for vd.8b I = 8).
 * Returns correctly formatted RegisterValue.
 */
template <typename Ta, typename Tb, int I>
RegisterValue vecShrnShift_imm(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    bool shrn2 = false) {
  const Ta* n = sourceValues[0].getAsVector<Ta>();

  uint64_t shift = metadata.operands[2].imm;

  Tb out[16 / sizeof(Tb)] = {0};
  int index = shrn2 ? I : 0;
  for (int i = 0; i < I; i++) {
    out[index + i] = static_cast<Tb>(std::trunc(n[i] >> shift));
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `sshr vd, vn, #imm`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecSshrShift_imm(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  const T* n = sourceValues[1].getAsVector<T>();
  uint64_t shift = metadata.operands[2].imm;
  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I; i++) {
    out[i] = static_cast<T>(std::trunc(n[i] >> shift));
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `addp rd, vn`.
 * T represents the type of sourceValues (e.g. for vn.2d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * Returns correctly formatted RegisterValue. */
template <typename T, int I>
RegisterValue vecSumElems_2ops(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  T out = 0;
  for (int i = 0; i < I; i++) {
    out += n[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `xtn{2} vd, vn`.
 * D represents the type of the dest. register (e.g. for vd.s, D = uint32_t).
 * N represents the type of the source register (e.g. for vn.d, N = uint64_t).
 * I represents the number of elements in the output vector to be
 * updated (i.e. for vd.4s I = 4).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N, int I>
RegisterValue vecXtn(srcValContainer& sourceValues, bool isXtn2) {
  const D* d;
  if (isXtn2) d = sourceValues[0].getAsVector<D>();
  const N* n = sourceValues[isXtn2 ? 1 : 0].getAsVector<N>();

  D out[16 / sizeof(D)] = {0};
  int index = 0;

  for (int i = 0; i < I; i++) {
    if (isXtn2 & (i < (I / 2))) {
      out[i] = d[i];
    } else {
      out[i] = static_cast<D>(n[index]);
      index++;
    }
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `tbl Vd.Ta, {Vn.16b,
 * ... Vn+3.16b}, Vm.Ta`.
 * I represents the number of elements in the output vector to be updated
 * (i.e. for vd.8b I = 8, vd.16b I = 16). Only 8 or 16 is valid for TBL
 * instructions.
 * Returns correctly formatted RegisterValue. */
template <int I>
RegisterValue vecTbl(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  // Vd and Vm are only valid in format 8b or 16b
  assert(I == 8 || I == 16);

  // Vm contains the indices to fetch from table
  const int8_t* Vm =
      sourceValues[metadata.operandCount - 2]
          .getAsVector<int8_t>();  // final operand is vecMovi_imm

  // All sourceValues except the first and last are the vector registers to
  // construct the table from
  const uint8_t n_table_regs = metadata.operandCount - 2;

  // Create table from vectors. All table sourceValues must be of 16b format.
  const uint16_t tableSize = 16 * n_table_regs;
  std::vector<uint8_t> table(tableSize, 0);
  for (int i = 0; i < n_table_regs; i++) {
    const int8_t* currentVector = sourceValues[i].getAsVector<int8_t>();
    for (int j = 0; j < 16; j++) {
      table[16 * i + j] = currentVector[j];
    }
  }

  int8_t out[16 / sizeof(int8_t)] = {0};
  for (int i = 0; i < I; i++) {
    int8_t index = Vm[i];

    // If an index is out of range for the table, the result for that lookup
    // is 0
    if (index >= tableSize) {
      out[i] = 0;
      continue;
    }

    out[i] = table[index];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `rev<16,32,64> Vd.T,
 * Vn.T`.
 * T represents the type of elements to be reversed (e.g. for Vn.d, T =
 * uint64_t).
 * V represents the variant: 16-bit, 32-bit, 64-bit. (e.g. for 64-bit each
 * doubleword of the vector will be reversed).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vd.8b I = 8).
 * It is only valid for T to be a same or smaller width than V.
 * Returns correctly formatted RegisterValue. */
template <typename T, int V, int I>
RegisterValue vecRev(srcValContainer& sourceValues) {
  const T* source = sourceValues[0].getAsVector<T>();
  int element_size = (sizeof(T) * 8);
  int datasize = I * element_size;
  int container_size = V;
  int n_containers = datasize / container_size;
  int elements_per_container = container_size / element_size;

  int element = 0;
  int rev_element;
  T out[16 / sizeof(T)] = {0};
  for (int c = 0; c < n_containers; c++) {
    rev_element = element + elements_per_container - 1;
    for (int e = 0; e < elements_per_container; e++) {
      out[rev_element] = source[element];
      element++;
      rev_element--;
    }
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `trn1 Vd.T, Vn.T,
 * Vm.T`.
 * T represents the type of sourceValues (e.g. for vn.d, T = uint64_t).
 * I represents the number of sourceValues (e.g. for vn.8b, I = 8).
 * Returns formatted Register Value. */
template <typename T, int I>
RegisterValue vecTrn1(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I / 2; i++) {
    out[2 * i] = n[2 * i];
    out[(2 * i) + 1] = m[2 * i];
  }

  return {out, 256};
}

/** Helper function for NEON instructions with the format `trn2 Vd.T, Vn.T,
 * Vm.T`.
 * T represents the type of sourceValues (e.g. for Vn.d, T = uint64_t).
 * I represents the number of sourceValues (e.g. for Vn.8b, I = 8).
 * Returns formatted Register Value. */
template <typename T, int I>
RegisterValue vecTrn2(srcValContainer& sourceValues) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I / 2; i++) {
    out[2 * i] = n[(2 * i) + 1];
    out[(2 * i) + 1] = m[(2 * i) + 1];
  }

  return {out, 256};
}

/** Helper function for NEON instructions with the format `uzp<1,2> Vd.T,
 * Vn.T, Vm.T`.
 * T represents the type of sourceValues (e.g. for Vn.d, T = uint64_t).
 * I represents the number of sourceValues (e.g. for Vn.8b, I = 8).
 * Returns formatted Register Value. */
template <typename T, int I>
RegisterValue vecUzp(srcValContainer& sourceValues, bool isUzp1) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[16 / sizeof(T)] = {0};
  for (int i = 0; i < I / 2; i++) {
    int index = isUzp1 ? (2 * i) : (2 * i) + 1;
    out[i] = n[index];
    out[(I / 2) + i] = m[index];
  }

  return {out, 256};
}

/** Helper function for NEON instructions with the format `zip<1,2> vd.T,
 * vn.T, vm.T`.
 * T represents the type of sourceValues (e.g. for vn.d, T = uint64_t).
 * I represents the number of elements in the output array to be updated (e.g.
 * for vn.8b, I = 8).
 * Returns formatted Register Value. */
template <typename T, int I>
RegisterValue vecZip(srcValContainer& sourceValues, bool isZip2) {
  const T* n = sourceValues[0].getAsVector<T>();
  const T* m = sourceValues[1].getAsVector<T>();

  T out[16 / sizeof(T)] = {0};
  int index = isZip2 ? (I / 2) : 0;
  for (int i = 0; i < I / 2; i++) {
    out[2 * i] = n[index];
    out[(2 * i) + 1] = m[index];
    index++;
  }

  return {out, 256};
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng