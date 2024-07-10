#pragma once

#include <array>
#include <cstdint>

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for SVE instructions with the format `add zd, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAdd_3ops(std::vector<RegisterValue>& operands,
                          const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] + m[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `add zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAdd_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] + imm;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `add zdn, pg/m, zdn,
 * const`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAddPredicated_const(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  bool isFP = std::is_floating_point<T>::value;
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* d = operands[1].getAsVector<T>();
  const auto con = isFP ? metadata.operands[3].fp : metadata.operands[3].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = d[i] + con;
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `add zdn, pg/m, zdn,
 * zm`.
 * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAddPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* d = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = d[i] + m[i];
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for NEON instructions with the format `addv dd, pg, zn`.
 * T represents the type of operands (e.g. for zn.s, T = uint32_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAddvPredicated(std::vector<RegisterValue>& operands,
                                const uint16_t VL_bits, bool isSigned = false) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  uint64_t out = 0;

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      if (isSigned)
        out += static_cast<int64_t>(n[i]);
      else
        out += static_cast<uint64_t>(n[i]);
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `adr zd, [zn, zm{,
 * lsl #<1,2,3>}]`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveAdr_lsl(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  const int mbytes = 1 << metadata.operands[2].shift.value;
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] + (m[i] * mbytes);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `adr zd, [zn, zm{,
 * {u|s}xtw} #<1,2,3>}]`.
 * T represents the type of operands (e.g. for zn.d and uxtw, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
RegisterValue sveAdr_xtw(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool isUnsigned = false) {
  const uint16_t partition_num = VL_bits / 64;
  const int mbytes = 1 << metadata.operands[2].shift.value;

  if (isUnsigned) {
    const uint64_t* n = operands[0].getAsVector<uint64_t>();
    const uint64_t* m = operands[1].getAsVector<uint64_t>();
    uint64_t out[32] = {0};

    for (int i = 0; i < partition_num; i++) {
      out[i] = n[i] + (static_cast<uint64_t>(m[i] & 0xFFFFFFFF) * mbytes);
    }
    return {out, 256};
  } else {
    const int64_t* n = operands[0].getAsVector<int64_t>();
    const int64_t* m = operands[1].getAsVector<int64_t>();
    int64_t out[32] = {0};

    for (int i = 0; i < partition_num; i++) {
      out[i] = n[i] +
               (static_cast<int64_t>(static_cast<int32_t>(m[i] & 0xFFFFFFFF)) *
                mbytes);
    }
    return {out, 256};
  }
}

/** Helper function for SVE instructions with the format `asr zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = int64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::enable_if_t<std::is_signed_v<T>, RegisterValue> sveAsr_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = (n[i] >> imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `asr zdn, pg/m, zdn,
 * #imm`.
 * T represents the type of operands (e.g. for zn.d, T = int64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::enable_if_t<std::is_signed_v<T>, RegisterValue> sveAsrPredicated_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[3].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = (dn[i] >> imm);
    } else
      out[i] = dn[i];
  }
  return {out, 256};
}

/** Helper function for instructions with the format `cmp<eq, ge, gt, hi, hs,
 *le, lo, ls, lt, ne> pd, pg/z, zn, <zm, #imm>`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns tuple of type [pred result (array of 4 uint64_t), nzcv]. */
template <typename T>
std::tuple<std::array<uint64_t, 4>, uint8_t> sveCmpPredicated_toPred(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool cmpToImm, std::function<bool(T, T)> func) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m;
  T imm;
  if (cmpToImm)
    imm = static_cast<T>(metadata.operands[3].imm);
  else
    m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      if (cmpToImm)
        out[i / (64 / sizeof(T))] |= (func(n[i], imm)) ? (shifted_active) : 0;
      else
        out[i / (64 / sizeof(T))] |= (func(n[i], m[i])) ? (shifted_active) : 0;
    }
  }
  // Byte count = sizeof(T) as destination predicate is predicate of T bytes.
  return {out, getNZCVfromPred(out, VL_bits, sizeof(T))};
}

/** Helper function for SVE instructions with the format `cnt<b,d,h,s> rd{,
 * pattern{, #imm}}`.
 * T represents the type of operation (e.g. for CNTD, T = uint64_t).
 * Returns single value of type uint64_t. */
template <typename T>
uint64_t sveCnt_gpr(const simeng::arch::aarch64::InstructionMetadata& metadata,
                    const uint16_t VL_bits) {
  const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);

  const uint16_t elems =
      sveGetPattern(metadata.operandStr, (sizeof(T) * 8), VL_bits);
  return (uint64_t)(elems * imm);
}

/** Helper function for SVE instructions with the format `cntp xd, pg, pn`.
 * T represents the type of operands (e.g. for pn.d, T = uint64_t).
 * Returns single value of type uint64_t. */
template <typename T>
uint64_t sveCntp(std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
  const uint64_t* pg = operands[0].getAsVector<uint64_t>();
  const uint64_t* pn = operands[1].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  uint64_t count = 0;

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (pg[i / (64 / sizeof(T))] & shifted_active) {
      count += (pn[i / (64 / sizeof(T))] & shifted_active) ? 1 : 0;
    }
  }
  return count;
}

/** Helper function for SVE instructions with the format `fcm<ge, lt,...> pd,
 * pg/z, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns an array of 4 uint64_t elements. */
template <typename T>
std::array<uint64_t, 4> sveComparePredicated_vecsToPred(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool cmpToZero, std::function<bool(T, T)> func) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m;
  if (!cmpToZero) m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i / (64 / sizeof(T))] |=
          (func(n[i], cmpToZero ? 0.0 : m[i])) ? shifted_active : 0;
    }
  }
  return out;
}

/** Helper function for SVE instructions with the format `compact zd, pg, zn`
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveCompact(std::vector<RegisterValue>& operands,
                         const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  uint16_t index = 0;
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[index] = n[i];
      index++;
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `cpy zd, pg/m,
 * <w,x,v>n`
 * T represents the type of the destination elements (e.g. for zd.d, T =
 * int64_t).
 * D represents the type of operands (e.g. for x0, D = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T, typename D>
RegisterValue sveCpy_reg(std::vector<RegisterValue>& operands,
                         const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const D scalar = operands[2].get<D>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = scalar;
    } else {
      out[i] = d[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `cpy zd, pg/m, #imm{,
 * shift}`.
 * T represents the type of operands (e.g. for zd.d, T = int64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveCpyMerge_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const int16_t imm = metadata.operands[2].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = imm;
    } else {
      out[i] = n[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `cpy zd, pg/z, #imm{,
 * shift}`.
 * T represents the type of operands (e.g. for zd.d, T = int64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveCpyZero_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const int16_t imm = metadata.operands[2].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = imm;
    } else {
      out[i] = 0;
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `dec<b,d,h,s> xdn{,
 * pattern{, MUL #imm}}`.
 * T represents the type of operation (e.g. for DECD, T = uint64_t).
 * Returns single value of type uint64_t. */
template <typename T>
int64_t sveDec_scalar(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const int64_t n = operands[0].get<int64_t>();
  const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
  const uint16_t elems =
      sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
  return (n - static_cast<int64_t>(elems * imm));
}

/** Helper function for SVE instructions with the format `dup zd, <#imm{,
 * shift}, <w,x>n>`.
 * T represents the type of operands (e.g. for zd.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveDup_immOrScalar(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool useImm) {
  bool isFP = std::is_floating_point<T>::value;
  T imm;
  // Set the value to be duplicated
  if (useImm) {
    if (isFP) {
      // Use the fp member variable if the source is a floating point
      imm = metadata.operands[1].fp;
    } else if (metadata.operands[1].imm < 0x100) {
      // Read as a width of 8b if the immediate is less than 0x100
      imm = static_cast<int8_t>(metadata.operands[1].imm);
    } else {
      // Read as a width of 16b if the immediate is greater than 0x100
      imm = static_cast<int16_t>(metadata.operands[1].imm);
    }
  } else {
    imm = operands[0].get<T>();
  }
  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = imm;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `dup zd, zn[#imm]`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveDup_vecIndexed(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint16_t index =
      static_cast<uint16_t>(metadata.operands[1].vector_index);
  const T* n = operands[0].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  if (index < (VL_bits / (sizeof(T) * 8))) {
    const T element = n[index];
    for (int i = 0; i < partition_num; i++) {
      out[i] = element;
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `eor zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveEor_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = (n[i] ^ imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fabs zd,
 * pg/z, zn`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFabsPredicated(std::vector<RegisterValue>& operands,
                                const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = ::fabs(n[i]);
    } else {
      out[i] = d[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fadda rd,
 * pg, rn, zm`.
 * T represents the type of operands (e.g. for zm.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFaddaPredicated(std::vector<RegisterValue>& operands,
                                 const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T n = operands[1].get<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  out[0] = n;

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[0] += m[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `faddv rd,
 * pg, zm`.
 * T represents the type of operands (e.g. for zm.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFaddV(std::vector<RegisterValue>& operands,
                       const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[0] += n[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fcadd zdn, pg/m,
 * zdn, zm, #imm`.
 * T represents the type of operands (e.g. for zm.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFcaddPredicated(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();
  const uint32_t imm = metadata.operands[4].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < (partition_num / 2); i++) {
    T acc_r = dn[2 * i];
    T acc_i = dn[2 * i + 1];
    T elt2_r = m[2 * i];
    T elt2_i = m[2 * i + 1];

    uint64_t shifted_active1 = 1ull
                               << (((2 * i) % (64 / sizeof(T))) * sizeof(T));
    uint64_t shifted_active2 =
        1ull << (((2 * i + 1) % (64 / sizeof(T))) * sizeof(T));
    if (p[(2 * i) / (64 / sizeof(T))] & shifted_active1) {
      if (imm == 90) {
        elt2_i = 0.0 - elt2_i;
      }
      acc_r = acc_r + elt2_i;
    }
    if (p[(2 * i + 1) / (64 / sizeof(T))] & shifted_active2) {
      if (imm == 270) {
        elt2_r = 0.0 - elt2_r;
      }
      acc_i = acc_i + elt2_r;
    }
    out[2 * i] = acc_r;
    out[2 * i + 1] = acc_i;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fcmla zda, pg/m,
 * zn, zm, #imm`.
 * T represents the type of operands (e.g. for zm.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFcmlaPredicated(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* da = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();
  const uint32_t imm = metadata.operands[4].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  int sel_a = (imm == 0 || imm == 180) ? 0 : 1;
  int sel_b = (imm == 0 || imm == 180) ? 1 : 0;
  bool neg_i = (imm == 180 || imm == 270) ? true : false;
  bool neg_r = (imm == 90 || imm == 180) ? true : false;
  for (int i = 0; i < (partition_num / 2); i++) {
    T addend_r = da[2 * i];
    T addend_i = da[2 * i + 1];
    T elt1_a = n[2 * i + sel_a];
    T elt2_a = m[2 * i + sel_a];
    T elt2_b = m[2 * i + sel_b];
    uint64_t shifted_active1 = 1ull
                               << (((2 * i) % (64 / sizeof(T))) * sizeof(T));
    uint64_t shifted_active2 =
        1ull << (((2 * i + 1) % (64 / sizeof(T))) * sizeof(T));
    if (p[(2 * i) / (64 / sizeof(T))] & shifted_active1) {
      if (neg_r) {
        elt2_a = 0.0 - elt2_a;
      }
      addend_r = addend_r + (elt1_a * elt2_a);
    }
    if (p[(2 * i + 1) / (64 / sizeof(T))] & shifted_active2) {
      if (neg_i) {
        elt2_b = 0.0 - elt2_b;
      }
      addend_i = addend_i + (elt1_a * elt2_b);
    }
    out[2 * i] = addend_r;
    out[2 * i + 1] = addend_i;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fcpy zd, pg/m,
 * #const`.
 * T represents the type of operands (e.g. for zd.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFcpy_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* dn = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T imm = metadata.operands[2].fp;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = imm;
    } else {
      out[i] = dn[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fcvt zd,
 * pg/m, zn`.
 * D represents the destination vector register type (e.g. zd.s would be
 * int32_t).
 * N represents the source vector register type (e.g. zn.d would be double).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N>
RegisterValue sveFcvtPredicated(std::vector<RegisterValue>& operands,
                                const uint16_t VL_bits) {
  const D* d = operands[0].getAsVector<D>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const N* n = operands[2].getAsVector<N>();

  // Stores size of largest type out of D and N
  int lts = std::max(sizeof(D), sizeof(N));
  bool sourceLarger = (sizeof(D) < sizeof(N)) ? true : false;
  bool sameDandN = (sizeof(D) == sizeof(N)) ? true : false;

  const uint16_t partition_num = VL_bits / (lts * 8);
  D out[256 / sizeof(D)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / lts)) * lts);
    int indexOut = (sourceLarger) ? (2 * i) : i;
    int indexN = (!sameDandN) && (!sourceLarger) ? (2 * i) : i;

    if (p[i / (64 / lts)] & shifted_active) {
      if (n[indexN] > std::numeric_limits<D>::max())
        out[indexOut] = std::numeric_limits<D>::max();
      else if (n[indexN] < std::numeric_limits<D>::lowest())
        out[indexOut] = std::numeric_limits<D>::lowest();
      else
        out[indexOut] = static_cast<D>(n[indexN]);
    } else {
      out[indexOut] = d[indexOut];
    }
    if (sourceLarger) out[indexOut + 1] = d[indexOut + 1];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fcvtzs zd,
 * pg/m, zn`.
 * D represents the destination vector register type (e.g. zd.s would be
 * int32_t).
 * N represents the source vector register type (e.g. zn.d would be double).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N>
RegisterValue sveFcvtzsPredicated(std::vector<RegisterValue>& operands,
                                  const uint16_t VL_bits) {
  const D* d = operands[0].getAsVector<D>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const N* n = operands[2].getAsVector<N>();

  // Stores size of largest type out of D and N
  int lts = std::max(sizeof(D), sizeof(N));
  bool sameType = (sizeof(D) == sizeof(N)) ? true : false;
  bool sourceLarger = (sizeof(D) < sizeof(N)) ? true : false;

  const uint16_t partition_num = VL_bits / (lts * 8);
  D out[256 / sizeof(D)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / lts)) * lts);
    int indexOut = (sourceLarger) ? (2 * i) : i;
    int indexN = ((!sourceLarger) & (!sameType)) ? (2 * i) : i;

    if (p[i / (64 / lts)] & shifted_active) {
      if (n[indexN] > std::numeric_limits<D>::max())
        out[indexOut] = std::numeric_limits<D>::max();
      else if (n[indexN] < std::numeric_limits<D>::lowest())
        out[indexOut] = std::numeric_limits<D>::lowest();
      else
        out[indexOut] = static_cast<D>(std::trunc(n[indexN]));
      // Can be set to 0xFFFFFFFF as will only occur when D=int32_t.
      if (sourceLarger) out[indexOut + 1] = (n[indexN] < 0) ? 0xFFFFFFFFu : 0;
    } else {
      out[indexOut] = d[indexOut];
      if (sourceLarger) out[indexOut + 1] = d[indexOut + 1];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `<fdiv, fdivr>
 * zd, pg/m, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Reversed represents whether the opcode is fdivr and thus the input
 * operands should be reversed. Returns correctly formatted RegisterValue.
 */
template <typename T, bool Reversed = false>
std::enable_if_t<std::is_floating_point_v<T>, RegisterValue> sveFDivPredicated(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      const T op1 = Reversed ? m[i] : dn[i];
      const T op2 = Reversed ? dn[i] : m[i];
      if (op2 == 0)
        out[i] = sizeof(T) == 8 ? std::nan("") : std::nanf("");
      else
        out[i] = op1 / op2;
    } else
      out[i] = dn[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `{s,u}div{r}
 * zd, pg/m, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Reversed represents whether the opcode is {s,u}divr and thus the input
 * operands should be reversed. Returns correctly formatted RegisterValue.
 */
template <typename T, bool Reversed = false>
RegisterValue sveDivPredicated(std::vector<RegisterValue>& operands,
                               const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      const T op1 = Reversed ? m[i] : dn[i];
      const T op2 = Reversed ? dn[i] : m[i];
      if (op2 == 0)
        out[i] = 0;
      else
        out[i] = std::trunc(op1 / op2);
    } else
      out[i] = dn[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `{f}mad zd, pg/m, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMadPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = m[i] + (d[i] * n[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fmaxnm zdn, pg/m,
 * zdn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFmaxnm_vec(std::vector<RegisterValue>& operands,
                            const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = std::fmax(n[i], m[i]);
    else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fexpa zd, zn`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFexpa(std::vector<RegisterValue>& operands,
                       const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  uint64_t opMask = 0;
  // Shift calculated based on bits extracted and size of coeff
  uint64_t opShift = 0;
  switch (sizeof(T)) {
    case 2: {
      opMask = 0x3e0;
      opShift = 5;  // 10 bits coeff, bit 5 to 9 extracted
      break;
    }
    case 4: {
      opMask = 0x3fd0;
      opShift = 17;  // 23 bits coeff, bit 6 to 16 extracted
      break;
    }
    case 8: {
      opMask = 0x1ffd0;
      opShift = 46;  // 52 bits coeff, bit 6 to 16 extracted
      break;
    }
  }

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t coeff = 0x0;
    if (sizeof(T) == 2) {
      switch (n[i] & 0x1F) {
        case 0:
          coeff = 0x0000;
          break;
        case 1:
          coeff = 0x0016;
          break;
        case 2:
          coeff = 0x002d;
          break;
        case 3:
          coeff = 0x0045;
          break;
        case 4:
          coeff = 0x005d;
          break;
        case 5:
          coeff = 0x0075;
          break;
        case 6:
          coeff = 0x008e;
          break;
        case 7:
          coeff = 0x00a8;
          break;
        case 8:
          coeff = 0x00c2;
          break;
        case 9:
          coeff = 0x00dc;
          break;
        case 10:
          coeff = 0x00f8;
          break;
        case 11:
          coeff = 0x0114;
          break;
        case 12:
          coeff = 0x0130;
          break;
        case 13:
          coeff = 0x014d;
          break;
        case 14:
          coeff = 0x016b;
          break;
        case 15:
          coeff = 0x0189;
          break;
        case 16:
          coeff = 0x01a8;
          break;
        case 17:
          coeff = 0x01c8;
          break;
        case 18:
          coeff = 0x01e8;
          break;
        case 19:
          coeff = 0x0209;
          break;
        case 20:
          coeff = 0x022b;
          break;
        case 21:
          coeff = 0x024e;
          break;
        case 22:
          coeff = 0x0271;
          break;
        case 23:
          coeff = 0x0295;
          break;
        case 24:
          coeff = 0x02ba;
          break;
        case 25:
          coeff = 0x02e0;
          break;
        case 26:
          coeff = 0x0306;
          break;
        case 27:
          coeff = 0x032e;
          break;
        case 28:
          coeff = 0x0356;
          break;
        case 29:
          coeff = 0x037f;
          break;
        case 30:
          coeff = 0x03a9;
          break;
        case 31:
          coeff = 0x03d4;
          break;
      }
    } else if (sizeof(T) == 4) {
      switch (n[i] & 0x3F) {
        case 0:
          coeff = 0x000000;
          break;
        case 1:
          coeff = 0x0164d2;
          break;
        case 2:
          coeff = 0x02cd87;
          break;
        case 3:
          coeff = 0x043a29;
          break;
        case 4:
          coeff = 0x05aac3;
          break;
        case 5:
          coeff = 0x071f62;
          break;
        case 6:
          coeff = 0x08980f;
          break;
        case 7:
          coeff = 0x0a14d5;
          break;
        case 8:
          coeff = 0x0b95c2;
          break;
        case 9:
          coeff = 0x0d1adf;
          break;
        case 10:
          coeff = 0x0ea43a;
          break;
        case 11:
          coeff = 0x1031dc;
          break;
        case 12:
          coeff = 0x11c3d3;
          break;
        case 13:
          coeff = 0x135a2b;
          break;
        case 14:
          coeff = 0x14f4f0;
          break;
        case 15:
          coeff = 0x16942d;
          break;
        case 16:
          coeff = 0x1837f0;
          break;
        case 17:
          coeff = 0x19e046;
          break;
        case 18:
          coeff = 0x1b8d3a;
          break;
        case 19:
          coeff = 0x1d3eda;
          break;
        case 20:
          coeff = 0x1ef532;
          break;
        case 21:
          coeff = 0x20b051;
          break;
        case 22:
          coeff = 0x227043;
          break;
        case 23:
          coeff = 0x243516;
          break;
        case 24:
          coeff = 0x25fed7;
          break;
        case 25:
          coeff = 0x27cd94;
          break;
        case 26:
          coeff = 0x29a15b;
          break;
        case 27:
          coeff = 0x2b7a3a;
          break;
        case 28:
          coeff = 0x2d583f;
          break;
        case 29:
          coeff = 0x2f3b79;
          break;
        case 30:
          coeff = 0x3123f6;
          break;
        case 31:
          coeff = 0x3311c4;
          break;
        case 32:
          coeff = 0x3504f3;
          break;
        case 33:
          coeff = 0x36fd92;
          break;
        case 34:
          coeff = 0x38fbaf;
          break;
        case 35:
          coeff = 0x3aff5b;
          break;
        case 36:
          coeff = 0x3d08a4;
          break;
        case 37:
          coeff = 0x3f179a;
          break;
        case 38:
          coeff = 0x412c4d;
          break;
        case 39:
          coeff = 0x4346cd;
          break;
        case 40:
          coeff = 0x45672a;
          break;
        case 41:
          coeff = 0x478d75;
          break;
        case 42:
          coeff = 0x49b9be;
          break;
        case 43:
          coeff = 0x4bec15;
          break;
        case 44:
          coeff = 0x4e248c;
          break;
        case 45:
          coeff = 0x506334;
          break;
        case 46:
          coeff = 0x52a81e;
          break;
        case 47:
          coeff = 0x54f35b;
          break;
        case 48:
          coeff = 0x5744fd;
          break;
        case 49:
          coeff = 0x599d16;
          break;
        case 50:
          coeff = 0x5bfbb8;
          break;
        case 51:
          coeff = 0x5e60f5;
          break;
        case 52:
          coeff = 0x60ccdf;
          break;
        case 53:
          coeff = 0x633f89;
          break;
        case 54:
          coeff = 0x65b907;
          break;
        case 55:
          coeff = 0x68396a;
          break;
        case 56:
          coeff = 0x6ac0c7;
          break;
        case 57:
          coeff = 0x6d4f30;
          break;
        case 58:
          coeff = 0x6fe4ba;
          break;
        case 59:
          coeff = 0x728177;
          break;
        case 60:
          coeff = 0x75257d;
          break;
        case 61:
          coeff = 0x77d0df;
          break;
        case 62:
          coeff = 0x7a83b3;
          break;
        case 63:
          coeff = 0x7d3e0c;
          break;
      }
    } else if (sizeof(T) == 8) {
      switch (n[i] & 0x3F) {
        case 0:
          coeff = 0x0000000000000;
          break;
        case 1:
          coeff = 0x02C9A3E778061;
          break;
        case 2:
          coeff = 0x059B0D3158574;
          break;
        case 3:
          coeff = 0x0874518759BC8;
          break;
        case 4:
          coeff = 0x0B5586CF9890F;
          break;
        case 5:
          coeff = 0x0E3EC32D3D1A2;
          break;
        case 6:
          coeff = 0x11301D0125B51;
          break;
        case 7:
          coeff = 0x1429AAEA92DE0;
          break;
        case 8:
          coeff = 0x172B83C7D517B;
          break;
        case 9:
          coeff = 0x1A35BEB6FCB75;
          break;
        case 10:
          coeff = 0x1D4873168B9AA;
          break;
        case 11:
          coeff = 0x2063B88628CD6;
          break;
        case 12:
          coeff = 0x2387A6E756238;
          break;
        case 13:
          coeff = 0x26B4565E27CDD;
          break;
        case 14:
          coeff = 0x29E9DF51FDEE1;
          break;
        case 15:
          coeff = 0x2D285A6E4030B;
          break;
        case 16:
          coeff = 0x306FE0A31B715;
          break;
        case 17:
          coeff = 0x33C08B26416FF;
          break;
        case 18:
          coeff = 0x371A7373AA9CB;
          break;
        case 19:
          coeff = 0x3A7DB34E59FF7;
          break;
        case 20:
          coeff = 0x3DEA64C123422;
          break;
        case 21:
          coeff = 0x4160A21F72E2A;
          break;
        case 22:
          coeff = 0x44E086061892D;
          break;
        case 23:
          coeff = 0x486A2B5C13CD0;
          break;
        case 24:
          coeff = 0x4BFDAD5362A27;
          break;
        case 25:
          coeff = 0x4F9B2769D2CA7;
          break;
        case 26:
          coeff = 0x5342B569D4F82;
          break;
        case 27:
          coeff = 0x56F4736B527DA;
          break;
        case 28:
          coeff = 0x5AB07DD485429;
          break;
        case 29:
          coeff = 0x5E76F15AD2148;
          break;
        case 30:
          coeff = 0x6247EB03A5585;
          break;
        case 31:
          coeff = 0x6623882552225;
          break;
        case 32:
          coeff = 0x6A09E667F3BCD;
          break;
        case 33:
          coeff = 0x6DFB23C651A2F;
          break;
        case 34:
          coeff = 0x71F75E8EC5F74;
          break;
        case 35:
          coeff = 0x75FEB564267C9;
          break;
        case 36:
          coeff = 0x7A11473EB0187;
          break;
        case 37:
          coeff = 0x7E2F336CF4E62;
          break;
        case 38:
          coeff = 0x82589994CCE13;
          break;
        case 39:
          coeff = 0x868D99B4492ED;
          break;
        case 40:
          coeff = 0x8ACE5422AA0DB;
          break;
        case 41:
          coeff = 0x8F1AE99157736;
          break;
        case 42:
          coeff = 0x93737B0CDC5E5;
          break;
        case 43:
          coeff = 0x97D829FDE4E50;
          break;
        case 44:
          coeff = 0x9C49182A3F090;
          break;
        case 45:
          coeff = 0xA0C667B5DE565;
          break;
        case 46:
          coeff = 0xA5503B23E255D;
          break;
        case 47:
          coeff = 0xA9E6B5579FDBF;
          break;
        case 48:
          coeff = 0xAE89F995AD3AD;
          break;
        case 49:
          coeff = 0xB33A2B84F15FB;
          break;
        case 50:
          coeff = 0xB7F76F2FB5E47;
          break;
        case 51:
          coeff = 0xBCC1E904BC1D2;
          break;
        case 52:
          coeff = 0xC199BDD85529C;
          break;
        case 53:
          coeff = 0xC67F12E57D14B;
          break;
        case 54:
          coeff = 0xCB720DCEF9069;
          break;
        case 55:
          coeff = 0xD072D4A07897C;
          break;
        case 56:
          coeff = 0xD5818DCFBA487;
          break;
        case 57:
          coeff = 0xDA9E603DB3285;
          break;
        case 58:
          coeff = 0xDFC97337B9B5F;
          break;
        case 59:
          coeff = 0xE502EE78B3FF6;
          break;
        case 60:
          coeff = 0xEA4AFA2A490DA;
          break;
        case 61:
          coeff = 0xEFA1BEE615A27;
          break;
        case 62:
          coeff = 0xF50765B6E4540;
          break;
        case 63:
          coeff = 0xFA7C1819E90D8;
          break;
      }
    }
    uint64_t op = (n[i] & opMask) << opShift;
    out[i] = op | coeff;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fminnm zdn, pg/m,
 * zdn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFminnm_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T m = static_cast<T>(metadata.operands[3].fp);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = std::fmin(n[i], m);
    else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fminnm zdn, pg/m,
 * zdn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFminnm_vec(std::vector<RegisterValue>& operands,
                            const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = std::fmin(n[i], m[i]);
    else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `{f}mls zd, pg/m, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMlsPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = d[i] - (n[i] * m[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `{f}msb zd, pg/m, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMsbPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = m[i] - (d[i] * n[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fmul zd, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFmul_3ops(std::vector<RegisterValue>& operands,
                           const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] * m[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fneg zd, pg/m, zn`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFnegPredicated(std::vector<RegisterValue>& operands,
                                const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = -n[i];
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fnmls zd, pg/m, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFnmlsPredicated(std::vector<RegisterValue>& operands,
                                 const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = -d[i] + (n[i] * m[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fnmsb zdn, pg/m, zm,
 * za`.
 * T represents the type of operands (e.g. for zdn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFnmsbPredicated(std::vector<RegisterValue>& operands,
                                 const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* m = operands[2].getAsVector<T>();
  const T* a = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = -a[i] + n[i] * m[i];
    else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `frecpe zd, zn`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFrecpe(std::vector<RegisterValue>& operands,
                        const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = 1.0f / n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `frintn zd, pg/m,
 * zn`.
 * T represents the vector type (e.g. zd.s would be float).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::enable_if_t<std::is_floating_point_v<T>, RegisterValue>
sveFrintnPredicated(std::vector<RegisterValue>& operands,
                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      // Get truncation
      T trunc = std::trunc(n[i]);
      // On tie, round to nearest even
      if (std::fabs(n[i] - trunc) == static_cast<T>(0.5)) {
        T addand = (trunc > static_cast<T>(0.0)) ? static_cast<T>(1)
                                                 : static_cast<T>(-1);
        // If odd, add the addand
        out[i] = (std::fmod(trunc, static_cast<T>(2.0)) == static_cast<T>(0.0))
                     ? trunc
                     : (trunc + addand);
      } else {
        // Else, round to nearest
        out[i] = std::round(n[i]);
      }
    } else {
      out[i] = d[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `frsqrte zd, zn`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFrsqrte(std::vector<RegisterValue>& operands,
                         const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = 1.0f / sqrtf(n[i]);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fsqrt zd,
 * pg/m, zn`.
 * T represents the type of operands (e.g. for zn.d, T = double).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFsqrtPredicated_2vecs(std::vector<RegisterValue>& operands,
                                       const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = ::sqrt(n[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `inc<b, d, h, w>
 * xdn{, pattern{, MUL #imm}}`.
 * T represents the type of operation (e.g. for INCB, T = int8_t).
 * Returns single value of type int64_t. */
template <typename T>
int64_t sveInc_gprImm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const int64_t n = operands[0].get<int64_t>();
  const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
  const uint16_t elems =
      sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
  int64_t out = n + (elems * imm);
  return out;
}

/** Helper function for SVE instructions with the format `inc<b, d, h, w>
 * zdn{, pattern{, #imm}}`.
 * T represents the type of operands (e.g. for zdn.d, T = int64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveInc_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  typename std::make_signed<T>::type out[256 / sizeof(T)] = {0};
  const uint16_t elems =
      sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);

  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] + (elems * imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `incp xdn, pm`.
 * T represents the type of operands (e.g. for pm.d, T = uint64_t).
 * Returns single value of type uint64_t. */
template <typename T>
uint64_t sveIncp_gpr(std::vector<RegisterValue>& operands,
                     const uint16_t VL_bits) {
  const uint64_t dn = operands[0].get<uint64_t>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  uint64_t count = 0;

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      count++;
    }
  }
  return dn + count;
}

/** Helper function for SVE instructions with the format `index zd, <#imm,
 * rn>, <#imm, rm>`.
 * D represents the vector register type (e.g. zd.b would be int8_t).
 * N represents the GPR type (e.g. for xn, xm, D = int64).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N = int8_t>
RegisterValue sveIndex(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool op1isImm, bool op2isImm) {
  const int op2Index = op1isImm ? 0 : 1;
  const auto n = op1isImm ? static_cast<int8_t>(metadata.operands[1].imm)
                          : static_cast<N>(operands[0].get<N>());
  const auto m = op2isImm ? static_cast<int8_t>(metadata.operands[2].imm)
                          : static_cast<N>(operands[op2Index].get<N>());

  const uint16_t partition_num = VL_bits / (sizeof(D) * 8);
  D out[256 / sizeof(D)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = static_cast<D>(n + (i * m));
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `clastb vdn, pg, vdn,
 * zm`.
 * T represents the vector register type (e.g. zd.d would be uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveClastBScalar(std::vector<RegisterValue>& operands,
                              const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out;

  // Get last active element
  int lastElem = -1;
  for (int i = partition_num - 1; i >= 0; i--) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      lastElem = i;
      break;
    }
  }
  // If no active lane has been found, select highest element instead
  out = (lastElem == -1) ? dn[0] : m[lastElem];

  return {out, 256};
}

/** Helper function for SVE instructions with the format `lastb vd, pg, zn`.
 * T represents the vector register type (e.g. zd.d would be uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveLastBScalar(std::vector<RegisterValue>& operands,
                             const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out;

  // Get last active element
  int lastElem = 0;
  for (int i = partition_num - 1; i >= 0; i--) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      lastElem = i;
      break;
    }
    // If no active lane has been found, select highest element instead
    if (i == 0) lastElem = partition_num - 1;
  }

  out = n[lastElem];
  return {out, 256};
}

/** Helper function for SVE instructions with the format `<AND, EOR, ...>
 * pd, pg/z, pn, pm`.
 * T represents the type of operands (e.g. for pn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::array<uint64_t, 4> sveLogicOp_preds(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits,
    std::function<uint64_t(uint64_t, uint64_t)> func) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const uint64_t* n = operands[1].getAsVector<uint64_t>();
  const uint64_t* m = operands[2].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i / (64 / sizeof(T))] |=
          (func(n[i / (64 / sizeof(T))], m[i / (64 / sizeof(T))]) &
           shifted_active);
    }
  }
  return out;
}

/** Helper function for SVE instructions with the format `<AND, EOR, ...>
 * zd, pg/m, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveLogicOpPredicated_3vecs(std::vector<RegisterValue>& operands,
                                         const uint16_t VL_bits,
                                         std::function<T(T, T)> func) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = func(dn[i], m[i]);
    else
      out[i] = dn[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `<AND, EOR, ...>
 * zd, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveLogicOpUnPredicated_3vecs(std::vector<RegisterValue>& operands,
                                           const uint16_t VL_bits,
                                           std::function<T(T, T)> func) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = func(n[i], m[i]);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `lsl zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveLsl_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  typename std::make_signed<T>::type out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = (n[i] << imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `lsr zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::enable_if_t<std::is_unsigned_v<T>, RegisterValue> sveLsr_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = (n[i] >> imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `lsr zdn, pg/m, zdn,
 * #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::enable_if_t<std::is_unsigned_v<T>, RegisterValue> sveLsrPredicated_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[3].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = (dn[i] >> imm);
    } else
      out[i] = dn[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `max zdn, zdn,
 * #imm`.
 * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMax_vecImm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = std::max(n[i], imm);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `max zdn, zdn,
 * #imm`.
 * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMaxPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = std::max(n[i], m[i]);
    } else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `mla zd, pg/m, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMlaPredicated_vecs(std::vector<RegisterValue>& operands,
                                    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();
  const T* m = operands[3].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = d[i] + (n[i] * m[i]);
    else
      out[i] = d[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fmla zda, zn,
 * zm[index]`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMlaIndexed_vecs(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();
  const size_t index = static_cast<size_t>(metadata.operands[2].vector_index);

  const uint16_t elemsPer128 = 128 / (sizeof(T) * 8);
  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (size_t i = 0; i < partition_num; i += elemsPer128) {
    const T zm_elem = m[i + index];
    for (size_t j = 0; j < elemsPer128; j++) {
      out[i + j] = d[i + j] + (n[i + j] * zm_elem);
    }
  }

  return {out, 256};
}

/** Helper function for SVE instructions with the format `movprfx zd,
 * pg/z, zn`.
 * T represents the type of operands (e.g. for zd.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMovprfxPredicated_destToZero(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
  // TODO: Adopt hint logic of the MOVPRFX instruction
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = n[i];
    } else {
      out[i] = 0;
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `movprfx zd,
 * pg/m, zn`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMovprfxPredicated_destUnchanged(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
  // TODO: Adopt hint logic of the MOVPRFX instruction
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = n[i];
    } else {
      out[i] = d[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `mul zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMul_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] * imm;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `mul zdn, pg/m, zdn,
 * <zm, #imm>`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveMulPredicated(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits, bool useImm) {
  bool isFP = std::is_floating_point<T>::value;
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m;
  T imm;
  if (useImm)
    imm = isFP ? metadata.operands[3].fp : metadata.operands[3].imm;
  else
    m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = n[i] * (useImm ? imm : m[i]);
    } else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `{s|u}mulh zdn, pg/m,
 * zdn, zm`.
 * T represents the type of operands (e.g. for zn.s, T = int32_t).
 * TT represents the type twice the length of T (e.g. for T = int8_t, TT =
 * int16_T).
 * Returns correctly formatted RegisterValue. */
// TODO : Support for 64 bit mulh operations.
template <typename T, typename TT>
RegisterValue sveMulhPredicated(std::vector<RegisterValue>& operands,
                                const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      bool isNeg = false;
      T a = n[i];
      T b = m[i];
      if (a < 0) {
        isNeg = !isNeg;
        a = 0 - a;
      }
      if (b < 0) {
        isNeg = !isNeg;
        b = 0 - b;
      }
      TT tmp = (static_cast<TT>(a) * static_cast<TT>(b));
      if (isNeg) tmp = 0 - tmp;

      out[i] = static_cast<T>(tmp >> (sizeof(T) * 8));
    } else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `umulh zdn, pg/m,
 * zdn, zm`.
 * T represents the type of operands (e.g. for zn.s, T = int32_t).
 * TT represents the type twice the length of T (e.g. for T = int8_t, TT =
 * int16_T).
 * Returns correctly formatted RegisterValue. */
RegisterValue sveUmulhPredicated64bits(std::vector<RegisterValue>& operands,
                                       const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const uint64_t* n = operands[1].getAsVector<uint64_t>();
  const uint64_t* m = operands[2].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / 64;
  uint64_t out[32] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % 8) * 8);
    if (p[i / 8] & shifted_active) {
      out[i] = mulhi(n[i], m[i]);
    } else
      out[i] = n[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `orr zdn, zdn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveOrr_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] | imm;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `orr zd, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveOrr_3vecs(std::vector<RegisterValue>& operands,
                           const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] | m[i];
  }
  return {out, 256};
}

/** Helper function for SVE2 instructions with the format `psel pd, pn,
 * pm.t[wa, #imm]`.
 * T represents the type of operands (e.g. for pm.d, T =
 * uint64_t). Returns an array of 4 uint64_t elements. */
template <typename T>
std::array<uint64_t, 4> svePsel(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* pn = operands[0].getAsVector<uint64_t>();
  const uint64_t* pm = operands[1].getAsVector<uint64_t>();
  const uint32_t wa = operands[2].get<uint32_t>();
  const uint32_t imm = metadata.operands[2].sme_index.disp;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);

  uint32_t index = (wa + imm) % partition_num;
  uint64_t shifted_active = 1ull << ((index % (64 / sizeof(T))) * sizeof(T));

  std::array<uint64_t, 4> out = {0, 0, 0, 0};
  if (pm[index / (64 / sizeof(T))] & shifted_active) {
    out = {pn[0], pn[1], pn[2], pn[3]};
  }

  return out;
}

/** Helper function for SVE instructions with the format `pfirst pdn, pg,
 * pdn`. Returns an array of 4 uint64_t elements. */
std::array<uint64_t, 4> svePfirst(std::vector<RegisterValue>& operands,
                                  const uint16_t VL_bits) {
  const uint16_t partition_num = VL_bits / 8;
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const uint64_t* dn = operands[1].getAsVector<uint64_t>();
  // Set destination d as source n to copy all false lanes and the active
  // lanes beyond the first
  std::array<uint64_t, 4> out = {dn[0], dn[1], dn[2], dn[3]};

  // Get the first active lane and set same lane in destination predicate
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64)));
    if (p[i / 64] & shifted_active) {
      out[i / 64] |= shifted_active;
      break;
    }
  }
  return out;
}

/** Helper function for SVE instructions with the format `ptrue pd{,
 * pattern}.
 * T represents the type of operands (e.g. for pd.d, T = uint64_t).
 * Returns an array of 4 uint64_t elements. */
template <typename T>
std::array<uint64_t, 4> svePtrue(
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  // Get pattern
  const uint16_t count =
      sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
  // Exit early if count == 0
  if (count == 0) return out;

  for (int i = 0; i < partition_num; i++) {
    if (i < count) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
      out[i / (64 / sizeof(T))] |= shifted_active;
    }
  }
  return out;
}

/** Helper function for SVE instructions with the format `punpk<hi,lo> pd.h,
 * pn.b`.
 * If `isHI` = false, then PUNPKLO is performed.
 * Returns an array of 4 uint64_t elements. */
std::array<uint64_t, 4> svePunpk(std::vector<RegisterValue>& operands,
                                 const uint16_t VL_bits, bool isHi) {
  const uint64_t* n = operands[0].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / 8;
  std::array<uint64_t, 4> out = {0, 0, 0, 0};
  uint16_t index = isHi ? (partition_num / 2) : 0;

  for (int i = 0; i < partition_num / 2; i++) {
    if (n[index / 64] & 1ull << index % 64) {
      out[i / 32] |= 1ull << ((i * 2) % 64);
    }
    index++;
  }
  return out;
}

/** Helper function for SVE instructions with the format `rev pd, pn`.
 * T represents the type of operands (e.g. for pd.d, T = uint64_t).
 * Returns an array of 4 uint64_t elements. */
template <typename T>
std::array<uint64_t, 4> sveRev_predicates(std::vector<RegisterValue>& operands,
                                          const uint16_t VL_bits) {
  const uint64_t* n = operands[0].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};
  uint16_t index = partition_num - 1;

  for (int i = 0; i < partition_num; i++) {
    uint64_t rev_shifted_active = 1ull
                                  << ((index % (64 / sizeof(T))) * sizeof(T));
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    out[index / (64 / (sizeof(T)))] |=
        ((n[i / (64 / (sizeof(T)))] & shifted_active) == shifted_active)
            ? rev_shifted_active
            : 0;
    index--;
  }
  return out;
}

/** Helper function for SVE instructions with the format `rev zd, zn`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveRev_vecs(std::vector<RegisterValue>& operands,
                          const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  uint16_t index = partition_num - 1;

  for (int i = 0; i < partition_num; i++) {
    out[i] = n[index];
    index--;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `sel zd, pg, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSel_zpzz(std::vector<RegisterValue>& operands,
                          const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active)
      out[i] = n[i];
    else
      out[i] = m[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `sminv rd, pg, zn`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSminv(std::vector<RegisterValue>& operands,
                       const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out = std::numeric_limits<T>::max();

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) out = std::min(out, n[i]);
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `splice zd, pg, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSplice(std::vector<RegisterValue>& operands,
                        const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* n = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  // Get last active element
  int lastElem = 0;
  for (int i = partition_num - 1; i >= 0; i--) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      lastElem = i;
      break;
    }
  }

  // Extract region from n as denoted by predicate p. Copy region into the
  // lowest elements of the destination operand
  bool active = false;
  int index = 0;
  for (int i = 0; i <= lastElem; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) active = true;
    if (active) {
      out[index] = n[i];
      index++;
    }
  }

  // Set any unassigned elements to the lowest elements in m
  int elemsLeft = partition_num - index;
  for (int i = 0; i < elemsLeft; i++) {
    out[index] = m[i];
    index++;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `sub zd, zn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSub_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T imm = static_cast<T>(metadata.operands[2].imm);

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] - imm;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `Sub zd, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSub_3vecs(std::vector<RegisterValue>& operands,
                           const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    out[i] = n[i] - m[i];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `fsubr zdn, pg/m,
 * zdn, #imm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveFsubrPredicated_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T m = metadata.operands[3].fp;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = m - dn[i];
    } else {
      out[i] = dn[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `Subr zdn, pg/m, zdn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSubrPredicated_3vecs(std::vector<RegisterValue>& operands,
                                      const uint16_t VL_bits) {
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const T* m = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = m[i] - dn[i];
    } else {
      out[i] = dn[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `Sub zdn, pg/m, zdn,
 * #imm`.
 * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveSubPredicated_imm(
    std::vector<RegisterValue>& operands,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    const uint16_t VL_bits) {
  bool isFP = std::is_floating_point<T>::value;
  const uint64_t* p = operands[0].getAsVector<uint64_t>();
  const T* dn = operands[1].getAsVector<T>();
  const auto imm = isFP ? metadata.operands[3].fp : metadata.operands[3].imm;

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      out[i] = dn[i] - imm;
    } else {
      out[i] = dn[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `sxt<b,h,w> zd, pg,
 * zn`.
 * T represents the type of vector registers (e.g. for zd.d, T = int64_t).
 * C represents the type of the cast required - is linked to instruction
 * variant used (i.e. sxtw requires int32_t).
 * Returns correctly formatted RegisterValue. */
template <typename T, typename C>
RegisterValue sveSxtPredicated(std::vector<RegisterValue>& operands,
                               const uint16_t VL_bits) {
  const T* d = operands[0].getAsVector<T>();
  const uint64_t* p = operands[1].getAsVector<uint64_t>();
  const T* n = operands[2].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
    if (p[i / (64 / sizeof(T))] & shifted_active) {
      // Cast to C to get 'least significant sub-element'
      // Then cast back to T to sign-extend this 'sub-element'
      out[i] = static_cast<T>(static_cast<C>(n[i]));
    } else {
      out[i] = d[i];
    }
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `trn1 zd, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveTrn1_3vecs(std::vector<RegisterValue>& operands,
                            const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < (partition_num / 2); i++) {
    out[2 * i] = n[(2 * i)];
    out[(2 * i) + 1] = m[(2 * i)];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `trn2 zd, zn, zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveTrn2_3vecs(std::vector<RegisterValue>& operands,
                            const uint16_t VL_bits) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < (partition_num / 2); i++) {
    out[2 * i] = n[(2 * i) + 1];
    out[(2 * i) + 1] = m[(2 * i) + 1];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `<s,u>unpk>hi,lo> zd,
 * zn`.
 * D represents the type of the destination register (e.g. <u>int32_t for
 * zd.s).
 * N represents the type of the source register (e.g. <u>int8_t for zn.b).
 * Returns correctly formatted RegisterValue. */
template <typename D, typename N>
RegisterValue sveUnpk_vecs(std::vector<RegisterValue>& operands,
                           const uint16_t VL_bits, bool isHi) {
  const N* n = operands[0].getAsVector<N>();

  const uint16_t partition_num = VL_bits / (sizeof(N) * 8);
  D out[256 / sizeof(D)] = {0};

  int index = isHi ? (partition_num / 2) : 0;

  for (int i = 0; i < partition_num / 2; i++) {
    out[i] = static_cast<D>(n[index]);
    index++;
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `uqdec<b, d, h, w>
 * <x,w>d{, pattern{, MUL #imm}}`.
 * D represents the type of dest. register(e.g. uint32_t for wd).
 * N represents the type of the operation (e.g. for UQDECH, N = 16u).
 * Returns single value of type uint64_t. */
template <typename D, uint64_t N>
uint64_t sveUqdec(std::vector<RegisterValue>& operands,
                  const simeng::arch::aarch64::InstructionMetadata& metadata,
                  const uint16_t VL_bits) {
  const D d = operands[0].get<D>();
  const uint8_t imm = metadata.operands[1].imm;
  const uint16_t count = sveGetPattern(metadata.operandStr, N, VL_bits);

  // The range of possible values does not fit in the range of any integral
  // type, so a double is used as an intermediate value. The end result must
  // be saturated to fit in uint64_t.
  auto intermediate = double(d) - (imm * count);
  if (intermediate < 0) {
    return (uint64_t)0;
  }
  return (uint64_t)(d - (imm * count));
}

/** Helper function for SVE instructions with the format `uzp<1,2> pd, pn,
 * pm`.
 * T represents the type of operands (e.g. for pn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
std::array<uint64_t, 4> sveUzp_preds(std::vector<RegisterValue>& operands,
                                     const uint16_t VL_bits, bool isUzp1) {
  const uint64_t* n = operands[0].getAsVector<uint64_t>();
  const uint64_t* m = operands[1].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  // Create a bit mask of ones of width sizeof(T)
  const uint64_t bitmask = (1ull << sizeof(T)) - 1;
  for (int i = 0; i < partition_num / 2; i++) {
    // UZP1 concatenates even elements. UZP2 concatenates odd.
    int index = isUzp1 ? (2 * i) : (2 * i) + 1;
    // Select start of element at index, move to LSB, and extract full element
    // width with bitmask
    const uint64_t value = (n[index / (64 / sizeof(T))] >>
                            (index % (64 / sizeof(T)) * sizeof(T))) &
                           bitmask;
    // Shift extracted element to the correct destination element i
    out[i / (64 / (sizeof(T)))] |= value << (i % (64 / sizeof(T)) * sizeof(T));
  }
  for (int i = 0; i < partition_num / 2; i++) {
    int index = isUzp1 ? (2 * i) : (2 * i) + 1;
    int destIndex = partition_num / 2 + i;
    // Select start of element at index, move to LSB, and extract full element
    // width with bitmask
    const uint64_t value = (m[index / (64 / sizeof(T))] >>
                            (index % (64 / sizeof(T)) * sizeof(T))) &
                           bitmask;
    // Shift extracted element to the correct destination element i
    out[destIndex / (64 / sizeof(T))] |=
        value << (destIndex % (64 / sizeof(T)) * sizeof(T));
  }
  return out;
}

/** Helper function for SVE instructions with the format `uzp<1,2> zd, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveUzp_vecs(std::vector<RegisterValue>& operands,
                          const uint16_t VL_bits, bool isUzp1) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  for (int i = 0; i < partition_num / 2; i++) {
    // UZP1 concatenates even elements. UZP2 concatenates odd.
    int index = isUzp1 ? (2 * i) : (2 * i) + 1;
    out[i] = n[index];
  }
  for (int i = 0; i < partition_num / 2; i++) {
    int index = isUzp1 ? (2 * i) : (2 * i) + 1;
    out[partition_num / 2 + i] = m[index];
  }
  return {out, 256};
}

/** Helper function for SVE instructions with the format `while<ge, gt, hi,
 * hs, le, lo, ls, lt> pd, <w,x>n, <w,x>m`. T represents the type of operands
 * n and m (e.g. for wn, T = uint32_t). P represents the type of operand p
 * (e.g. for pd.b, P = uint8_t). Returns tuple of type [pred results (array of
 * 4 uint64_t), nzcv]. */
template <typename T, typename P>
std::tuple<std::array<uint64_t, 4>, uint8_t> sveWhile(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits,
    std::function<bool(T, T)> func) {
  const T n = operands[0].get<T>();
  const T m = operands[1].get<T>();

  const uint16_t partition_num = VL_bits / (sizeof(P) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  for (int i = 0; i < partition_num; i++) {
    // Determine whether lane should be active and shift to align with
    // element in predicate register.
    uint64_t shifted_active =
        func((n + i), m) ? 1ull << ((i % (64 / (sizeof(P))) * (sizeof(P)))) : 0;
    out[i / (64 / (sizeof(P)))] |= shifted_active;
  }
  // Byte count = sizeof(P) as destination predicate is predicate of P
  // bytes.
  uint8_t nzcv = getNZCVfromPred(out, VL_bits, sizeof(P));
  return {out, nzcv};
}

/** Helper function for SVE instructions with the format `while<rw, wr> pd,
 * xn, xm`. T represents the type of operand p (e.g. for pd.b, P = uint8_t).
 * Returns tuple of type [pred results (array of 4 uint64_t), nzcv]. */
template <typename T>
std::tuple<std::array<uint64_t, 4>, uint8_t> sveWhileAddrConflict(
    std::vector<RegisterValue>& operands, const uint16_t VL_bits,
    bool isRW = false) {
  const uint64_t n = operands[0].get<uint64_t>();
  const uint64_t m = operands[1].get<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  // Get the number of elements between the passed addresses
  signed long long diff = m - n;
  if (isRW) diff = std::abs(diff);
  const int64_t addrDiff = diff / static_cast<int64_t>(sizeof(T));

  for (int i = 0; i < partition_num; i++) {
    // Determine whether the selected lane should be active and shift to align
    // with element in predicate register.
    uint64_t shifted_active =
        (addrDiff <= 0 || i < addrDiff)
            ? 1ull << ((i % (64 / (sizeof(T))) * (sizeof(T))))
            : 0;
    out[i / (64 / (sizeof(T)))] |= shifted_active;
  }
  // Byte count = sizeof(T) as destination predicate is predicate of T
  // bytes.
  uint8_t nzcv = getNZCVfromPred(out, VL_bits, sizeof(T));
  return {out, nzcv};
}

/** Helper function for SVE instructions with the format `zip<1,2> pd, pn,
 * pm`.
 * T represents the type of operands (e.g. for pn.d, T = uint64_t).
 * Returns an array of 4 uint64_t elements. */
template <typename T>
std::array<uint64_t, 4> sveZip_preds(std::vector<RegisterValue>& operands,
                                     const uint16_t VL_bits, bool isZip2) {
  const uint64_t* n = operands[0].getAsVector<uint64_t>();
  const uint64_t* m = operands[1].getAsVector<uint64_t>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  std::array<uint64_t, 4> out = {0, 0, 0, 0};

  bool interleave = false;
  int index = isZip2 ? (partition_num / 2) : 0;
  for (int i = 0; i < partition_num; i++) {
    uint64_t shifted_active = 1ull << ((index % (64 / sizeof(T))) * sizeof(T));
    if (interleave) {
      out[i / (64 / sizeof(T))] |=
          ((m[index / (64 / sizeof(T))] & shifted_active) == shifted_active)
              ? static_cast<uint64_t>(1ull
                                      << ((i % (64 / sizeof(T))) * sizeof(T)))
              : 0;
      index++;
    } else {
      out[i / (64 / sizeof(T))] |=
          ((n[index / (64 / sizeof(T))] & shifted_active) == shifted_active)
              ? static_cast<uint64_t>(1ull
                                      << ((i % (64 / sizeof(T))) * sizeof(T)))
              : 0;
    }
    interleave = !interleave;
  }
  return out;
}

/** Helper function for SVE instructions with the format `zip<1,2> zd, zn,
 * zm`.
 * T represents the type of operands (e.g. for zn.d, T = uint64_t).
 * Returns correctly formatted RegisterValue. */
template <typename T>
RegisterValue sveZip_vecs(std::vector<RegisterValue>& operands,
                          const uint16_t VL_bits, bool isZip2) {
  const T* n = operands[0].getAsVector<T>();
  const T* m = operands[1].getAsVector<T>();

  const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
  T out[256 / sizeof(T)] = {0};

  bool interleave = false;
  int index = isZip2 ? (partition_num / 2) : 0;
  for (int i = 0; i < partition_num; i++) {
    if (interleave) {
      out[i] = m[index];
      index++;
    } else {
      out[i] = n[index];
    }
    interleave = !interleave;
  }
  return {out, 256};
}

/** Helper function for SVE instructions store instructions to merge
 * consecutive active elements into blocks to be written.
 * T represents the size of the vector elements (e.g. for zn.d, T = uint64_t).
 * C represents the size of the memory elements (e.g. for st1w, C = uint32_t).
 * Return a vector of RegisterValues.  */
template <typename T, typename C = T>
std::vector<RegisterValue> sve_merge_store_data(const T* d, const uint64_t* p,
                                                uint16_t vl_bits) {
  std::vector<RegisterValue> outputData;

  uint16_t numVecElems = (vl_bits / (8 * sizeof(T)));
  // Determine how many predicate elements are present per uint64_t.
  uint16_t predsPer64 = (64 / sizeof(T));

  // Determine size of array based on the size of the memory access (This is
  // the C specifier in sve instructions)
  std::array<C, 256 / sizeof(C)> mData;
  uint16_t mdSize = 0;

  for (uint16_t x = 0; x < numVecElems; x++) {
    // Determine mask to get predication for active element.
    uint64_t shiftedActive = 1ull << ((x % predsPer64) * sizeof(T));
    if (p[x / predsPer64] & shiftedActive) {
      // std::cerr << x << ":" << std::hex << static_cast<C>(d[x]) << std::dec
      //           << std::endl;
      mData[mdSize] = static_cast<C>(d[x]);
      mdSize++;
    } else if (mdSize) {
      outputData.push_back(
          RegisterValue((char*)mData.data(), mdSize * sizeof(C)));
      mdSize = 0;
    }
  }
  if (mdSize) {
    outputData.push_back(
        RegisterValue((char*)mData.data(), mdSize * sizeof(C)));
  }
  return outputData;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
