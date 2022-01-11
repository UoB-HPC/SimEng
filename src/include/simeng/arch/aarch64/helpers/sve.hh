#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "ExecuteHelperFunctions.hh"
#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class sveHelp {
 public:
  /** Helper function for SVE instructions with the format `add zd, zn, zm`. */
  template <typename T>
  static std::array<T, (256 / sizeof(T))> sveAdd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      const uint16_t VL_bits) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<T, (256 / sizeof(T))> out = {0};
    for (int i = 0; i < partition_num; i++) {
      out[i] = n[i] + m[i];
    }
    return out;
  }

  /** Helper function for SVE instructions with the format `and zdn, pg/z, zdn,
   * zm`. */
  template <typename T>
  static std::array<T, (256 / sizeof(T))> sveAndPredicated_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      const uint16_t VL_bits) {
    const uint64_t* g = operands[0].getAsVector<uint64_t>();
    const T* dn = operands[1].getAsVector<T>();
    const T* m = operands[2].getAsVector<T>();

    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<T, (256 / sizeof(T))> out = {0};
    for (int i = 0; i < partition_num; i++) {
      uint64_t shifted_active = 1ull << ((i % (64 / sizeof(T))) * sizeof(T));
      if (g[i / (64 / sizeof(T))] & shifted_active)
        out[i] = dn[i] & m[i];
      else
        out[i] = dn[i];
    }
    return out;
  }

  /** Helper function for SVE instructions with the format `dup zd, #imm{,
   * shift}`. */
  template <typename T>
  static std::array<T, (256 / sizeof(T))> sveDup_imm(
      struct simeng::arch::aarch64::InstructionMetadata metadata,
      const uint16_t VL_bits) {
    const int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);
    const uint16_t partition_num = VL_bits / (sizeof(T) * 8);
    std::array<T, (256 / sizeof(T))> out = {0};

    for (int i = 0; i < partition_num; i++) {
      out[i] = imm;
    }
    return out;
  }

  /** Helper function for SVE instructions with the format `ptrue pd{, pattern}.
   * T represents the predicate type (i.e. pd.b would be uint8_t).
   */
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

  /** Helper function for SVE instructions with the format `whilelo pd, {w,x}n,
   * {w,x}m`.
   * T represents the type of operands n and m (i.e. uint32_t for wn).
   * P represents the type of operand p (i.e. uint8_t for pd.b).
   */
  template <typename T, typename P>
  static std::tuple<std::array<uint64_t, 4>, uint8_t> sveWhilelo(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      const uint16_t VL_bits) {
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
    // Byte count = sizeof(P) as destination predicate is predicate of P bytes.
    return {out, ExecHelpFunc::getNZCVfromPred(out, VL_bits, sizeof(P))};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng