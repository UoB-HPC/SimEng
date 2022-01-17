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
  static std::array<T, 256> vecAdd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<T>(n[i] + m[i]);
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `addp rd, vn`.
   * I represents the number of elements in the input array to be summed.
   */
  template <typename T, int I>
  static std::array<T, 256> vecSumElems_2ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[0] += n[i];
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `addp vd, vn, vm`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecAddp_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    std::array<T, 256> out = {0};
    uint8_t offset = I / 2;
    for (int i = 0; i < I; i++) {
      if (i < offset) {
        out[i] = static_cast<T>(n[i * 2] + n[(i * 2) + 1]);
      } else {
        out[i] =
            static_cast<T>(m[(i - offset) * 2] + m[((i - offset) * 2) + 1]);
      }
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `bic vd, vn, vm`.
   * I represents the number of elements in the output array to be updated (i.e.
   * for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecBic_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = n[i] & ~m[i];
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `bic vd, #imm{, lsl
   * #shift}`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecBicShift_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T* d = operands[0].getAsVector<T>();
    T imm = ~shiftValue(static_cast<T>(metadata.operands[1].imm),
                        metadata.operands[1].shift.type,
                        metadata.operands[1].shift.value);
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = d[i] & imm;
    }
    return out;
  }

  /** Helper function for instructions with the format `cm<eq, ge, gt, hi, hs,
   *le, lt> vd, vn, <vm, #0>`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecCompare(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      std::function<bool(T, T)> func, bool cmpToZero) {
    const T* n = operands[0].getAsVector<T>();
    const T* m;
    if (!cmpToZero) m = operands[1].getAsVector<T>();
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      if (!cmpToZero)
        out[i] = func(n[i], m[i]) ? static_cast<T>(-1) : 0;
      else
        out[i] = func(n[i], 0) ? static_cast<T>(-1) : 0;
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `dup <rd, vd>,
   * <vn[index], rn>`.
   *I represents the number of elements in the output array to be updated (i.e.
   *for vd.8b the final 8 elements in the output array will be 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecDup_gprOrIndex(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata, bool useGpr) {
    int index = useGpr ? 0 : metadata.operands[1].vector_index;
    T element =
        useGpr ? operands[0].get<T>() : operands[0].getAsVector<T>()[index];
    std::array<T, 256> out = {0};
    std::fill_n(std::begin(out), I, element);
    return out;
  }

  /** Helper function for NEON instructions with the format `<AND, EOR, ...> vd,
   *  vn, vm`. T represents the vector register type (i.e. vd.16b would be
   * uint8_t). I represents the number of elements in the output array to be
   *updated (i.e. for vd.8b the final 8 elements in the output array will be
   *0).*/
  template <typename T, int I>
  static std::array<T, 256> vecLogicOp_3vecs(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      std::function<T(T, T)> func) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = func(n[i], m[i]);
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `movi vd, #imm`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecMovi_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T bits = static_cast<T>(metadata.operands[1].imm);
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = bits;
    }
    return out;
  }

  /** Helper function for NEON instructions with the format `movi vd, #imm{, lsl
   * #shift}`.
   * I represents the number of elements in the output array to be
   * updated (i.e. for vd.8b the final 8 elements in the output array will be
   * 0).
   */
  template <typename T, int I>
  static std::array<T, 256> vecMoviShift_imm(
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    const T bits = shiftValue(static_cast<T>(metadata.operands[1].imm),
                              metadata.operands[1].shift.type,
                              metadata.operands[1].shift.value);
    std::array<T, 256> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = bits;
    }
    return out;
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng