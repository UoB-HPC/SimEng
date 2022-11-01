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
  static RegisterValue sveAdd_3ops(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveAddPredicated_vecs(
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static RegisterValue sveAddvPredicated(std::vector<RegisterValue>& operands,
                                         const uint16_t VL_bits) {
    const uint64_t* p = operands[0].getAsVector<uint64_t>();
    const T* n = operands[1].getAsVector<T>();

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    uint64_t out = 0;

    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
      if (p[i / (64 / sizeof(T))] & shifted_active)
        out += static_cast<uint64_t>(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `adr zd, [zn, zm{,
   * lsl #<1,2,3>}]`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveAdr_packedOffsets(
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

  /** Helper function for instructions with the format `cmp<eq, ge, gt, hi, hs,
   *le, lo, ls, lt, ne> pd, pg/z, zn, <zm, #imm>`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns tuple of type [pred result (array of 4 uint64_t), nzcv]. */
  template <typename T>
  static std::tuple<std::array<uint64_t, 4>, uint8_t> sveCmpPredicated_toPred(
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
          out[i / (64 / sizeof(T))] |=
              (func(n[i], m[i])) ? (shifted_active) : 0;
      }
    }
    // Byte count = sizeof(T) as destination predicate is predicate of T bytes.
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

    const uint16_t elems =
        AuxFunc::sveGetPattern(metadata.operandStr, (sizeof(T) * 8), VL_bits);
    return (uint64_t)(elems * imm);
  }

  /** Helper function for SVE instructions with the format `cntp xd, pg, pn`.
   * T represents the type of operands (e.g. for pn.d, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveCntp(std::vector<RegisterValue>& operands,
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

  /** Helper function for SVE instructions with the format `cpy zd, pg/z, #imm{,
   * shift}`.
   * T represents the type of operands (e.g. for zd.d, T = int64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveCpy_imm(
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
  static int64_t sveDec_scalar(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const int64_t n = operands[0].get<int64_t>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
    const uint16_t elems =
        AuxFunc::sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
    return (n - static_cast<int64_t>(elems * imm));
  }

  /** Helper function for SVE instructions with the format `dup zd, <#imm{,
   * shift}, <w,x>n>`.
   * T represents the type of operands (e.g. for zd.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveDup_immOrScalar(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits, bool useImm) {
    bool isFP = std::is_floating_point<T>::value;
    T imm;
    if (useImm)
      imm = isFP ? metadata.operands[1].fp
                 : static_cast<int8_t>(metadata.operands[1].imm);
    else
      imm = operands[0].get<T>();
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

  /** Helper function for SVE instructions with the format `fabs zd,
   * pg/z, zn`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFabsPredicated(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveFaddaPredicated(std::vector<RegisterValue>& operands,
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

  /** Helper function for SVE instructions with the format `fcadd zdn, pg/m,
   * zdn, zm, #imm`.
   * T represents the type of operands (e.g. for zm.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFcaddPredicated(
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
  static RegisterValue sveFcmlaPredicated(
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
  static RegisterValue sveFcpy_imm(
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
  static RegisterValue sveFcvtPredicated(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveFcvtzsPredicated(std::vector<RegisterValue>& operands,
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static RegisterValue sveFmul_3ops(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveFnegPredicated(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveFnmlsPredicated(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveFnmsbPredicated(std::vector<RegisterValue>& operands,
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
   * N represents the source vector register type (e.g. zn.d would be
   * double).
   * Returns correctly formatted RegisterValue. */
  template <typename D, typename N>
  static RegisterValue sveFrintnPredicated(std::vector<RegisterValue>& operands,
                                           const uint16_t VL_bits) {
    const D* d = operands[0].getAsVector<D>();
    const uint64_t* p = operands[1].getAsVector<uint64_t>();
    const N* n = operands[2].getAsVector<N>();

    const uint16_t partition_num = VL_bits / (sizeof(N) * 8);
    D out[256 / sizeof(D)] = {0};

    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(N))) * sizeof(N));
      if (p[i / (64 / sizeof(N))] & shifted_active) {
        out[i] = AuxFunc::roundToNearestTiesToEven<N, D>(n[i]);
      } else {
        out[i] = d[i];
      }
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `fsqrt zd,
   * pg/m, zn`.
   * T represents the type of operands (e.g. for zn.d, T = double).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveFsqrtPredicated_2vecs(
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static int64_t sveInc_gprImm(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const int64_t n = operands[0].get<int64_t>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
    const uint16_t elems =
        AuxFunc::sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
    int64_t out = n + (elems * imm);
    return out;
  }

  /** Helper function for SVE instructions with the format `inc<b, d, h, w>
   * zdn{, pattern{, #imm}}`.
   * T represents the type of operands (e.g. for zdn.d, T = int64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveInc_imm(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const T* n = operands[0].getAsVector<T>();
    const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    typename std::make_signed<T>::type out[256 / sizeof(T)] = {0};
    const uint16_t elems =
        AuxFunc::sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);

    for (int i = 0; i < partition_num; i++) {
      out[i] = n[i] + (elems * imm);
    }
    return {out, 256};
  }

  /** Helper function for SVE instructions with the format `incp xdn, pm`.
   * T represents the type of operands (e.g. for pm.d, T = uint64_t).
   * Returns single value of type uint64_t. */
  template <typename T>
  static uint64_t sveIncp_gpr(std::vector<RegisterValue>& operands,
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

  /** Helper function for SVE instructions with the format `<AND, EOR, ...>
   * pd, pg/z, pn, pm`.
   * T represents the type of operands (e.g. for pn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static std::array<uint64_t, 4> sveLogicOp_preds(
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
  static RegisterValue sveLogicOpPredicated_3vecs(
      std::vector<RegisterValue>& operands, const uint16_t VL_bits,
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

  /** Helper function for SVE instructions with the format `lsl sz, zn, #imm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveLsl_imm(
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

  /** Helper function for SVE instructions with the format `max zdn, zdn,
   * #imm`.
   * T represents the type of operands (e.g. for zdn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMax_vecImm(
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
  static RegisterValue sveMaxPredicated_vecs(
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static RegisterValue sveMlaIndexed_vecs(
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
  static RegisterValue sveMovprfxPredicated_destToZero(
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
  static RegisterValue sveMovprfxPredicated_destUnchanged(
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

  /** Helper function for SVE instructions with the format `mul zdn, pg/m, zdn,
   * <zm, #imm>`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveMulPredicated(
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

  /** Helper function for SVE instructions with the format `mulh zdn, pg/m, zdn,
   * zm`.
   * T represents the type of operands (e.g. for zn.s, T = int32_t).
   * TT represents the type twice the length of T (e.g. for T = int8_t, TT =
   * int16_T).
   * Returns correctly formatted RegisterValue. */
  // TODO : Support for int64_t mulh operations.
  template <typename T, typename TT>
  static RegisterValue sveMulhPredicated(std::vector<RegisterValue>& operands,
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

  /** Helper function for SVE instructions with the format `orr zd, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveOrr_3vecs(std::vector<RegisterValue>& operands,
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
  static std::array<uint64_t, 4> svePsel(
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const uint64_t* pn = operands[0].getAsVector<uint64_t>();
    const uint64_t* pm = operands[1].getAsVector<uint64_t>();
    const uint32_t wa = operands[2].get<uint32_t>();
    const uint32_t imm = metadata.operands[2].sme_index.disp;

    uint32_t index = wa + imm;
    uint64_t shifted_active = 1ull << ((index % (64 / sizeof(T))) * sizeof(T));

    std::array<uint64_t, 4> out = {0, 0, 0, 0};
    if (pm[index / (64 / sizeof(T))] & shifted_active) {
      out = {pn[0], pn[1], pn[2], pn[3]};
    }

    return out;
  }

  /** Helper function for SVE instructions with the format `ptrue pd{,
   * pattern}.
   * T represents the type of operands (e.g. for pd.d, T = uint64_t).
   * Returns an array of 4 uint64_t elements. */
  template <typename T>
  static std::array<uint64_t, 4> svePtrue(
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<uint64_t, 4> out = {0, 0, 0, 0};

    // Get pattern
    const uint16_t count =
        AuxFunc::sveGetPattern(metadata.operandStr, sizeof(T) * 8, VL_bits);
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
  static std::array<uint64_t, 4> svePunpk(std::vector<RegisterValue>& operands,
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static RegisterValue sveRev_vecs(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveSel_zpzz(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveSminv(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveSub_3vecs(std::vector<RegisterValue>& operands,
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

  /** Helper function for SVE instructions with the format `Sub zdn, pg/m, zdn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveSubrPredicated_3vecs(
      std::vector<RegisterValue>& operands, const uint16_t VL_bits) {
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
  static RegisterValue sveSubPredicated_imm(
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
  static RegisterValue sveSxtPredicated(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveTrn1_3vecs(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveTrn2_3vecs(std::vector<RegisterValue>& operands,
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
  static RegisterValue sveUnpk_vecs(std::vector<RegisterValue>& operands,
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
      std::vector<RegisterValue>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      const uint16_t VL_bits) {
    const D d = operands[0].get<D>();
    const uint8_t imm = metadata.operands[1].imm;
    const uint16_t count =
        AuxFunc::sveGetPattern(metadata.operandStr, N, VL_bits);

    // The range of possible values does not fit in the range of any integral
    // type, so a double is used as an intermediate value. The end result must
    // be saturated to fit in uint64_t.
    auto intermediate = double(d) - (imm * count);
    if (intermediate < 0) {
      return (uint64_t)0;
    }
    return (uint64_t)(d - (imm * count));
  }

  /** Helper function for SVE instructions with the format `uzp<1,2> zd, zn,
   * zm`.
   * T represents the type of operands (e.g. for zn.d, T = uint64_t).
   * Returns correctly formatted RegisterValue. */
  template <typename T>
  static RegisterValue sveUzp_vecs(std::vector<RegisterValue>& operands,
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits,
      bool calcNZCV) {
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
      std::vector<RegisterValue>& operands, const uint16_t VL_bits,
      bool isZip2) {
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
  static RegisterValue sveZip_vecs(std::vector<RegisterValue>& operands,
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
