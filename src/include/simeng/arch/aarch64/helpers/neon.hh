#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class neonHelp {
 public:
  /** Helper function for NEON instructions with the format `add vd, vn, vm`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecAdd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<T>(n[i] + m[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `addp rd, vn`.
   * I represents the number of elements in the input array to be summed.
   */
  template <typename T, int I>
  static RegisterValue vecSumElems_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out = 0;
    for (int i = 0; i < I; i++) {
      out += n[i];
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `addp vd, vn, vm`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecAddp_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    uint8_t offset = I / 2;
    for (int i = 0; i < I; i++) {
      if (i < offset) {
        out[i] = static_cast<T>(n[i * 2] + n[(i * 2) + 1]);
      } else {
        out[i] =
            static_cast<T>(m[(i - offset) * 2] + m[((i - offset) * 2) + 1]);
      }
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `bic vd, vn, vm`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecBic_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = n[i] & ~m[i];
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `bic vd, #imm{, lsl
   * #shift}`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static RegisterValue vecBicShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
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
   * (i.e. for vd.8b I = 8). */
  template <int I>
  static RegisterValue vecBitwiseInsert(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      bool isBif) {
    const uint64_t* d = operands[0].getAsVector<uint64_t>();
    const uint64_t* n = operands[1].getAsVector<uint64_t>();
    const uint64_t* m = operands[2].getAsVector<uint64_t>();
    uint64_t out[2] = {0};
    for (int i = 0; i < (I / 8); i++) {
      out[i] = isBif ? (d[i] & m[i]) | (n[i] & ~m[i])
                     : (d[i] & ~m[i]) | (n[i] & m[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `bsl vd, vn,
   * vm`.
   * I represents the number of elements in the output array to be updated
   * (i.e. for vd.8b I = 8). */
  template <int I>
  static RegisterValue vecBsl(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const uint64_t* d = operands[0].getAsVector<uint64_t>();
    const uint64_t* n = operands[1].getAsVector<uint64_t>();
    const uint64_t* m = operands[2].getAsVector<uint64_t>();
    uint64_t out[2] = {0};
    for (int i = 0; i < (I / 8); i++) {
      out[i] = (d[i] & n[i]) | (~d[i] & m[i]);
    }
    return {out, 256};
  }

  /** Helper function for instructions with the format `cnt vd, vn`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b I = 8). */
  template <typename T, int I>
  static RegisterValue vecCountPerByte(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const uint8_t* n = operands[0].getAsVector<uint8_t>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      for (int j = 0; j < (sizeof(T) * 8); j++) {
        // Move queried bit to LSB and extract via an AND operator
        out[i] += ((n[i] >> j) & 1);
      }
    }
    return {out, 256};
  }

  /** Helper function for instructions with the format `cm<eq, ge, gt, hi, hs,
   *le, lt> vd, vn, <vm, #0>`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecCompare(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      bool cmpToZero, std::function<bool(T, T)> func) {
    const T* n = operands[0].getAsVector<T>();
    const T* m;
    if (!cmpToZero) m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = func(n[i], cmpToZero ? static_cast<T>(0) : m[i])
                   ? static_cast<T>(-1)
                   : 0;
    }
    return {out, 256};
  }

  /** Helper function for instructions with the format `fcm<eq, ge, gt, hi, hs,
   *le, lt> vd, vn, <vm, #0>`.
   * T represents operand type (i.e. vd.2d is double).
   * C represents comparison type (i.e. for T=float, comparison type is
   * uint32_t).
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).
   */
  template <typename T, typename C, int I>
  static RegisterValue vecFCompare(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      bool cmpToZero, std::function<bool(T, T)> func) {
    const T* n = operands[0].getAsVector<T>();
    const T* m;
    if (!cmpToZero) m = operands[1].getAsVector<T>();
    C out[16 / sizeof(C)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = func(n[i], cmpToZero ? static_cast<T>(0) : m[i])
                   ? static_cast<C>(-1)
                   : 0;
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `dup <rd, vd>,
   * <vn[index], rn>`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecDup_gprOrIndex(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata, bool useGpr) {
    int index = useGpr ? 0 : metadata.operands[1].vector_index;
    T element =
        useGpr ? operands[0].get<T>() : operands[0].getAsVector<T>()[index];
    T out[16 / sizeof(T)] = {0};
    std::fill_n(std::begin(out), I, element);
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `ext vd,
   *  vn, vm, #index`. T represents the vector register type (i.e. vd.16b would
   *be uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecExtVecs_index(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    const uint64_t index = static_cast<uint64_t>(metadata.operands[3].imm);
    T out[16 / sizeof(T)] = {0};

    for (int i = index; i < I; i++) {
      out[i - index] = n[i];
    }
    for (int i = 0; i < index; i++) {
      out[I - index + i] = m[i];
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fabs vd, vn`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecFabs_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = std::fabs(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `<NOT, ...> vd,
   *  vn`. T represents the vector register type (i.e. vd.16b would be
   * uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecLogicOp_2vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      std::function<T(T)> func) {
    const T* n = operands[0].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = func(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `<AND, EOR, ...> vd,
   *  vn, vm`. T represents the vector register type (i.e. vd.16b would be
   * uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecLogicOp_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      std::function<T(T, T)> func) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = func(n[i], m[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fmla vd,
   *  vn, vm`. T represents the vector register type (i.e. vd.16b would be
   * uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecFmla_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* d = operands[0].getAsVector<T>();
    const T* n = operands[1].getAsVector<T>();
    const T* m = operands[2].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i] + n[i] * m[i];
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fmla vd,
   *  vn, vm[index]`. T represents the vector register type (i.e. vd.16b would
   *be uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecFmlaIndexed_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
    const T* n = operands[1].getAsVector<T>();
    int index = metadata.operands[2].vector_index;
    const T m = operands[2].getAsVector<T>()[index];
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i] + n[i] * m;
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fmls vd,
   *  vn, vm`. T represents the vector register type (i.e. vd.16b would be
   * uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecFmls_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* d = operands[0].getAsVector<T>();
    const T* n = operands[1].getAsVector<T>();
    const T* m = operands[2].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i] - (n[i] * m[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fmls vd,
   *  vn, vm[index]`. T represents the vector register type (i.e. vd.16b would
   *be uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecFmlsIndexed_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
    const T* n = operands[1].getAsVector<T>();
    int index = metadata.operands[2].vector_index;
    const T m = operands[2].getAsVector<T>()[index];
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i] - n[i] * m;
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fmul rd,
   *  rn, vm[index]`. T represents the vector register type (i.e. sd would
   *be float).
   * I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).
   */
  template <typename T, int I>
  static RegisterValue vecFmulIndexed_vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    int index = metadata.operands[2].vector_index;
    const T* n = operands[0].getAsVector<T>();
    const T m = operands[1].getAsVector<T>()[index];
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = n[i] * m;
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fneg vd, vn`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecFneg_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = -n[i];
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `frsqrte vd, vn`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.2s the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecFrsqrte_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = 1.0f / sqrtf(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `frsqrts vd, vn,
   * vm`. I represents the number of elements in the output array to be updated
   * (i.e. for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecFrsqrts_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = (3.0f - n[i] * m[i]) / 2.0f;
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `fsqrt vd, vn`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.2s the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static RegisterValue vecFsqrt_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = ::sqrt(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `ins vd[index],
   *  rn`.
   * T represents the vector register type (i.e. vd.16b would
   *be uint8_t).
   * R represents the type of the GPR (i.e. wn would be uint32_t).
   * I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, typename R, int I>
  static RegisterValue vecInsIndex_gpr(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
    const T n = operands[1].get<R>();
    T out[16 / sizeof(T)] = {0};

    for (int i = 0; i < I; i++) {
      out[i] = d[i];
    }
    out[metadata.operands[0].vector_index] = n;
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `ins vd[index],
   *  vn[index]`.
   * T represents the vector register type (i.e. vd.16b would be uint8_t).
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static RegisterValue vecIns_2Index(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
    const T* n = operands[1].getAsVector<T>();

    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i];
    }
    out[metadata.operands[0].vector_index] =
        n[metadata.operands[1].vector_index];
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `movi vd, #imm`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static RegisterValue vecMovi_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    bool isFP = std::is_floating_point<T>::value;
    const T imm = isFP ? metadata.operands[1].fp
                       : static_cast<T>(metadata.operands[1].imm);
    T out[16 / sizeof(T)] = {0};
    std::fill_n(std::begin(out), I, imm);
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `movi vd, #imm{, lsl
   * #shift}`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static RegisterValue vecMoviShift_imm(
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
   * D represents the destination vector register type (i.e. vd.2d would be
   * double).
   * N represents the source vector register type (i.e. vd.2s would be int32_t).
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0). */
  template <typename D, typename N, int I>
  static RegisterValue vecScvtf_2vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      std::function<D(N)> func) {
    const N* n = operands[0].getAsVector<N>();
    D out[16 / sizeof(D)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<D>(n[i]);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `shl vd, vn, #imm`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static RegisterValue vecShlShift_vecImm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* n = operands[0].getAsVector<T>();
    int64_t shift = metadata.operands[2].imm;
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<T>(n[i] << shift);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `sminv sd, vn`.
   * I represents the number of elements in the source vector to be
   * accessed (i.e. for vn.4s I = 4).
   */
  template <typename T, int I>
  static RegisterValue vecSminv_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    T out = std::numeric_limits<T>::max();
    for (int i = 0; i < I; i++) {
      out = std::min(n[i], out);
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `sshr vd, vn, #imm`.
   * I represents the number of elements in the output vector to be
   * updated (i.e. for vd.4s I = 4).
   */
  template <typename T, int I>
  static RegisterValue vecSshrShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* n = operands[1].getAsVector<T>();
    uint64_t shift = metadata.operands[2].imm;
    T out[16 / sizeof(T)] = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<T>(std::trunc(n[i] >> shift));
    }
    return {out, 256};
  }

  /** Helper function for NEON instructions with the format `xtn{2} vd, vn`.
   * D represents the type of the dest. register (i.e. vd.s is uint32_t).
   * N represents the type of the source register (i.e. vn.d is uint64_t).
   * I represents the number of elements in the output vector to be
   * updated (i.e. for vd.4s I = 4).
   */
  template <typename D, typename N, int I>
  static RegisterValue vecXtn(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      bool isXtn2) {
    const D* d;
    if (isXtn2) d = operands[0].getAsVector<D>();
    const N* n = operands[isXtn2 ? 1 : 0].getAsVector<N>();

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
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng