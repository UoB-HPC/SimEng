#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `bfm rd, rn, #immr,
 * #imms`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T bfm_2imms(srcValContainer& sourceValues,
            const simeng::arch::aarch64::InstructionMetadata& metadata,
            bool signExtend, bool zeroDestReg) {
  uint8_t r = metadata.operands[2].imm;
  uint8_t s = metadata.operands[3].imm;
  T dest, source;
  if (!zeroDestReg) {
    dest = sourceValues[0].get<T>();
    source = sourceValues[1].get<T>();
  } else {
    dest = 0;
    source = sourceValues[0].get<T>();
  }
  return bitfieldManipulate(source, dest, r, s, signExtend);
}

/** Helper function for instructions with the format `extr rd, rn, rm, #lsb`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T extrLSB_registers(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata) {
  T n = sourceValues[0].get<T>();
  T m = sourceValues[1].get<T>();
  int64_t lsb = metadata.operands[3].imm;
  if (lsb == 0) return m;
  return (m >> lsb) | (n << ((sizeof(T) * 8) - lsb));
}

/** Helper function for instructions with the format `rbit rd, rn`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type uint64_t. */
template <typename T>
uint64_t rbit(srcValContainer& sourceValues,
              const simeng::arch::aarch64::InstructionMetadata& metadata) {
  int width = sizeof(T) * 8;

  uint8_t reversedNibble[16] = {0b0000, 0b1000, 0b0100, 0b1100, 0b0010, 0b1010,
                                0b0110, 0b1110, 0b0001, 0b1001, 0b0101, 0b1101,
                                0b0011, 0b1011, 0b0111, 0b1111};

  uint64_t n = sourceValues[0].get<uint64_t>();
  uint64_t result = 0;
  for (int i = 0; i < width; i += 4) {
    result <<= 4;
    result |= reversedNibble[n & 0b1111];
    n >>= 4;
  }
  return result;
}

/** Helper function for instructions with the format `rev rd, rn`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns array of uint8_t with number of elements = bytes in T. */
template <typename T>
std::array<uint8_t, sizeof(T)> rev(srcValContainer& sourceValues) {
  auto bytes = sourceValues[0].getAsVector<uint8_t>();
  std::array<uint8_t, sizeof(T)> reversed;
  // Copy `bytes` backwards onto `reversed`
  std::copy(bytes, bytes + sizeof(T), std::rbegin(reversed));
  return reversed;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng