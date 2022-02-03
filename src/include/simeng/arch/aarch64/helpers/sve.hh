#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class sveHelp {
 public:
  /** Helper function for SVE instructions with the format `add zd, zn, zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveAdd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `add zdn, pg/m, zdn,
   * const`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveAddPredicated_const(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveAddPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for instructions with the format `cmp<eq, ge, gt, hi, hs,
   *le, lo, ls, lt, ne> pd, pg/z, zn, <zm, #imm>`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns tuple of type [pred result (array of 4 uint64_t), nzcv]. */
  template <typename T>
  static std::tuple<std::array<uint64_t, 4>, uint8_t> sveCmpPredicated_toPred(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
          out[i / (64 / sizeof(T))] |=
              (func(n[i], m[i])) ? (shifted_active) : 0;
      }
    }
    // Byte count = sizeof(P) as destination predicate is predicate of P bytes.
    return {out, AuxFunc::getNZCVfromPred(out, VL_bits, sizeof(T))};
  }

  /** Helper function for SVE instructions with the format `cnt<b,d,h,s> rd{,
   * pattern{, #imm}}`.
   * T represents the type of operation (e.g. for CNTD, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveCnt_gpr(
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
    return (uint64_t)((VL_bits / (sizeof(T) * 8)) * imm);
  }

  /** Helper function for SVE instructions with the format `cntp xd, pg, pn`.
   * T represents the type of operands (e.g. for pn.d, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveCntp(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
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
  static std::array<uint64_t, 4> sveComparePredicated_vecsToPred(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `dec<b,d,h,s> xdn{,
   * pattern{, MUL #imm}}`.
   * T represents the type of operation (e.g. for DECD, T = uint64_t).
   * Returns single value of type uint64_t. */
  // TODO : Add support for patterns
  template <typename T>
  static uint64_t sveDec_scalar(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const uint64_t n = operands[0].get<uint64_t>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
    return (n - ((VL_bits / (sizeof(T) * 8)) * imm));
  }

  /** Helper function for SVE instructions with the format `dup zd, <#imm{,
   * shift}, <w,x>n>`.
   * T represents the type of operands (e.g. for zd.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveDup_immOrScalar(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits, bool useImm) {
    bool isFP = std::is_floating_point<T>::value;
    const auto imm =
        useImm ? (isFP ? metadata.operands[1].fp
                       : static_cast<int8_t>(metadata.operands[1].imm))
               : operands[0].get<T>();
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
  static RegisterValue sveDup_vecIndexed(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `fabs zd,
   * pg/z, zn`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFabsPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
   * pg/m, rn, zm`.
   * T represents the type of operands (e.g. for zm.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFaddaPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
    const uint64_t* p = operands[1].getAsVector<uint64_t>();
    const T n = operands[2].get<T>();
    const T* m = operands[3].getAsVector<T>();

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

  /** Helper function for SVE instructions with the format `fcvt zd,
   * pg/m, zn`.
   * D represents the destination vector register type (e.g. zd.s would be
   * int32_t).
   * N represents the source vector register type (e.g. zn.d would be double).
   * Returns correctly formatted RegisterValue. */
  template <typename D, typename N>
  static RegisterValue sveFcvtPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveFcvtzsPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `fmad zd, pg/m, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFmadPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `fmls zd, pg/m, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFmlsPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
        out[i] = d[i] + (-n[i] * m[i]);
      else
        out[i] = d[i];
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `fmsb zd, pg/m, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFmsbPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
        out[i] = m[i] + (-d[i] * n[i]);
      else
        out[i] = d[i];
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `fmul zd, zn, zm`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFmul_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveFnegPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
    const uint64_t* p = operands[0].getAsVector<uint64_t>();
    const T* n = operands[1].getAsVector<T>();

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    T out[256 / sizeof(T)] = {0};

    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
      if (p[i / (64 / sizeof(T))] & shifted_active)
        out[i] = -n[i];
      else
        out[i] = n[i];
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `fnmls zd, pg/m, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFnmlsPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveFnmsbPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `frintn zd, pg/m,
   * zn`.
   * D represents the destination vector register type (e.g. zd.s would be
   * int32_t).
   * N represents the source vector register type (e.g. zd.d would be
   * double).
   * Returns correctly formatted RegisterValue. */
  template <typename D, typename N>
  static RegisterValue sveFrintnPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
    const D* d = operands[0].getAsVector<D>();
    const uint64_t* p = operands[1].getAsVector<uint64_t>();
    const N* n = operands[2].getAsVector<N>();

    const uint16_t partition_num = VL_bits / (sizeof(N) * 8);
    D out[256 / sizeof(D)] = {0};

    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(N))) * sizeof(N));
      if (p[i / (64 / sizeof(N))] & shifted_active)
        out[i] = AuxFunc::doubleRoundToNearestTiesToEven(n[i]);
      else
        out[i] = d[i];
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `fsqrt zd,
   * pg/m, zn`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFsqrtPredicated_2vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
   * xdn{, pattern{, #imm}}`.
   * T represents the type of operation (e.g. for INCB, T = int8_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveInc_gprImm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const uint64_t n = operands[0].get<uint64_t>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
    uint64_t out = n + ((VL_bits / (sizeof(T) * 8)) * imm);
    return out;
  }

  /** Helper function for SVE instructions with the format `inc<b, d, h, w>
   * zdn{, pattern{, #imm}}`.
   * T represents the type of operands (e.g. for zdn.d, T = int64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveInc_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const T* n = operands[0].getAsVector<T>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    typename std::make_signed<T>::type out[256 / sizeof(T)] = {0};

    for (int i = 0; i < partition_num; i++) {
      out[i] = n[i] + ((VL_bits / (sizeof(T) * 8)) * imm);
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `incp xdn, pm`.
   * T represents the type of operands (e.g. for pm.d, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveIncp_gpr(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveIndex(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `<AND, EOR, ...>
   * pd, pg/z, pn, pm`.
   * T represents the type of operands (e.g. for pn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static std::array<uint64_t, 4> sveLogicOp_preds(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits,
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
   * zd, pg/z, zn, zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveLogicOpPredicated_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits, std::function<T(T, T)> func) {
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

  /** Helper function for SVE instructions with the format `lsl sz, zn, #imm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveLsl_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `max zdn, zdn,
   * #imm`.
   * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMax_vecImm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveMaxPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `fmla zd, pg/m, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMlaPredicated_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `movprfx zd,
   * pg/z, zn`.
   * T represents the type of operands (e.g. for zd.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMovprfxPredicated_destToZero(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
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
  static RegisterValue sveMovprfxPredicated_destUnchanged(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits) {
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

  /** Helper function for SVE instructions with the format `mul zd, pg/m, zn,
   * <zm, #imm>`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMulPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `orr zd, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveOrr_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `ptrue pd{,
   * pattern}.
   * T represents the type of operands (e.g. for pd.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static std::array<uint64_t, 4> svePtrue(const uint16_t VL_bits) {
    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<uint64_t, 4> out = {0, 0, 0, 0};

    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
      out[i / (64 / sizeof(T))] |= shifted_active;
    }
    return out;
  }

  /** Helper function for SVE instructions with the format `punpk<hi,lo> pd.h,
   * pn.b`.
   * If `isHI` = false, then PUNPKLO is performed.
   * Returns an array of 4 uint64_t elements. */
  static std::array<uint64_t, 4> svePunpk(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static std::array<uint64_t, 4> sveRev_predicates(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveRev_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `sel zd, pg/z, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveSel_zpzz(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
  static RegisterValue sveSminv(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `Sub zd, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveSub_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `sxt<b,h,w> zd, pg,
   * zn`.
   * T represents the type of vector registers (e.g. for zd.d, T = int64_t).
   * C represents the type of the cast required - is linked to instruction
   * variant used (i.e. sxtw requires int32_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T, typename C>
  static RegisterValue sveSxtPredicated(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `<s,u>unpk>hi,lo> zd,
   * zn`.
   * D represents the type of the destination register (e.g. <u>int32_t for
   * zd.s).
   * N represents the type of the source register (e.g. <u>int8_t for zn.b).
   * Returns correctly formatted RegisterValue. */
  template <typename D, typename N>
  static RegisterValue sveUnpk_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits, bool isHi) {
    const N* n = operands[0].getAsVector<N>();

    const uint16_t partition_num = VL_bits / (sizeof(D) * 8);
    D out[256 / sizeof(D)] = {0};

    for (int i = 0; i < partition_num; i++) {
      int index = isHi ? (partition_num + i) : i;
      out[i] = static_cast<D>(n[index]);
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `uqdec<b, d, h, w>
   * <x,w>d{, pattern{, MUL #imm}}`.
   * D represents the type of dest. register(e.g. uint32_t for wd).
   * N represents the type of the operation (e.g. for UQDECH, N = 16u).
   * Returns single value of type uint64_t. */
  template <typename D, uint64_t N>
  static uint64_t sveUqdec(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const D d = operands[0].get<D>();
    const uint8_t imm = metadata.operands[1].imm;

    // The range of possible values does not fit in the range of any integral
    // type, so a double is used as an intermediate value. The end result must
    // be saturated to fit in uint64_t.
    auto intermediate = double(d) - (imm * (VL_bits / N));
    if (intermediate < 0) {
      return (uint64_t)0;
    }
    return (uint64_t)(d - (imm * (VL_bits / N)));
  }

  /** Helper function for SVE instructions with the format `uzp<1,2> zd, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveUzp_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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

  /** Helper function for SVE instructions with the format `whilelo pd,
   * <w,x>n, <w,x>m`.
   * T represents the type of operands n and m (e.g. for wn, T = uint32_t).
   * P represents the type of operand p (e.g. for pd.b, P = uint8_t).
   * Returns tuple of type [pred results (array of 4 uint64_t), nzcv]. */
  template <typename T, typename P>
  static std::tuple<std::array<uint64_t, 4>, uint8_t> sveWhilelo(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits, bool calcNZCV) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();

    const uint16_t partition_num = VL_bits / (sizeof(P) * 8);
    std::array<uint64_t, 4> out = {0, 0, 0, 0};
    uint16_t index = 0;

    for (int i = 0; i < partition_num; i++) {
      // Determine whether lane should be active and shift to align with
      // element in predicate register.
      uint64_t shifted_active =
          (n + i) < m ? 1ull << ((i % (64 / (sizeof(P))) * (sizeof(P)))) : 0;
      out[index / (64 / (sizeof(P)))] =
          out[index / (64 / (sizeof(P)))] | shifted_active;
      index++;
    }
    // Byte count = sizeof(P) as destination predicate is predicate of P
    // bytes.
    uint8_t nzcv =
        calcNZCV ? AuxFunc::getNZCVfromPred(out, VL_bits, sizeof(P)) : 0;
    return {out, nzcv};
  }

  /** Helper function for SVE instructions with the format `zip<1,2> pd, pn,
   * pm`.
   * T represents the type of operands (e.g. for pn.d, T = uint64_t).
   * Returns an array of 4 uint64_t elements. */
  template <typename T>
  static std::array<uint64_t, 4> sveZip_preds(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const uint16_t VL_bits, bool isZip2) {
    const uint64_t* n = operands[0].getAsVector<uint64_t>();
    const uint64_t* m = operands[1].getAsVector<uint64_t>();

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<uint64_t, 4> out = {0, 0, 0, 0};

    bool interleave = false;
    int index = isZip2 ? (partition_num / 2) : 0;
    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull
                                << ((index % (64 / sizeof(T))) * sizeof(T));
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
  static RegisterValue sveZip_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
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
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng