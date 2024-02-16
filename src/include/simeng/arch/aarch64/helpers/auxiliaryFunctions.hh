#pragma once

#include <cmath>
#include <functional>
#include <limits>
#include <tuple>
#include <type_traits>

#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Returns a correctly formatted nzcv value. */
inline uint8_t nzcv(bool n, bool z, bool c, bool v) {
  return (n << 3) | (z << 2) | (c << 1) | v;
}

/** Performs a type agnostic unsigned add with carry. */
template <typename T>
inline std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>,
                        std::tuple<T, uint8_t>>
addWithCarry(T x, T y, bool carryIn) {
  T result = x + y + carryIn;

  bool n = (result >> (sizeof(T) * 8 - 1));
  bool z = (result == 0);

  // Trying to calculate whether `result` overflows (`x + y + carryIn > max`).
  bool c;
  if (carryIn && x + 1 == 0) {
    // Implies `x` is max; with a carry set, it will definitely overflow
    c = true;
  } else {
    // We know x + carryIn <= max, so can safely subtract and compare against
    // y max > x + y + c == max - x > y + c
    c = ((std::numeric_limits<T>::max() - x - carryIn) < y);
  }

  // Calculate whether signed result overflows
  bool v = false;
  typedef std::make_signed_t<T> ST;
  auto sx = static_cast<ST>(x);
  auto sy = static_cast<ST>(y);
  if (sx >= 0) {
    // Check if (x + y + c) > MAX
    // y > (MAX - x - c)
    v = sy > (std::numeric_limits<ST>::max() - sx - carryIn);
  } else {
    // Check if (x + y + c) < MIN
    // y < (MIN - x - c)
    v = sy < (std::numeric_limits<ST>::min() - sx - carryIn);
  }

  return {result, nzcv(n, z, c, v)};
}

/** Manipulate the bitfield `value` according to the logic of the (U|S)BFM
 * Armv9.2-a instructions. */
template <typename T>
inline std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T>
bitfieldManipulate(T value, T dest, uint8_t rotateBy, uint8_t sourceBits,
                   bool signExtend = false) {
  size_t bits = sizeof(T) * 8;

  T source;
  T destMask;
  uint8_t highestBit = sourceBits;
  if (sourceBits >= rotateBy) {
    // Mask of values [rotateBy:source+1]
    destMask = (static_cast<T>(-1) << (sourceBits - rotateBy + 1));
    source = value >> rotateBy;
    highestBit -= rotateBy;
  } else {
    T upper = (static_cast<T>(-1) << (bits - rotateBy));
    T lower = (static_cast<T>(-1) >> (rotateBy - sourceBits - 1));
    destMask = upper ^ lower;
    source = value << (bits - rotateBy);
    highestBit += (bits - rotateBy);
  }

  T result = (dest & destMask) | (source & ~destMask);

  if (!signExtend) {
    return result;
  }

  if (highestBit > bits) {
    // Nothing to do; implicitly sign-extended
    return result;
  }

  // Let the compiler do sign-extension for us.
  uint8_t shiftAmount = bits - highestBit - 1;
  // Shift the bitfield up, and cast to a signed type, so the highest bit is
  // now the sign bit
  auto shifted = static_cast<std::make_signed_t<T>>(result << shiftAmount);
  // Shift the bitfield back to where it was; as it's a signed type, the
  // compiler will sign-extend the highest bit
  return shifted >> shiftAmount;
}

/** Function to check if NZCV conditions hold. */
inline bool conditionHolds(uint8_t cond, uint8_t nzcv) {
  bool inverse = cond & 1;
  uint8_t upper = cond >> 1;
  bool n = (nzcv >> 3) & 1;
  bool z = (nzcv >> 2) & 1;
  bool c = (nzcv >> 1) & 1;
  bool v = nzcv & 1;
  bool result;
  switch (upper) {
    case 0b000:
      result = z;
      break;  // EQ/NE
    case 0b001:
      result = c;
      break;  // CS/CC
    case 0b010:
      result = n;
      break;  // MI/PL
    case 0b011:
      result = v;
      break;  // VS/VC
    case 0b100:
      result = (c && !z);
      break;  // HI/LS
    case 0b101:
      result = (n == v);
      break;  // GE/LT
    case 0b110:
      result = (n == v && !z);
      break;  // GT/LE
    default:  // 0b111, AL
      // AL returns true regardless of inverse value
      result = (true ^ inverse);
  }
  return (result ^ inverse);
}

/** Extend `value` according to `extendType`, and left-shift the result by
 * `shift`. Replicated from Instruction.cc */
inline uint64_t extendValue(uint64_t value, uint8_t extendType, uint8_t shift) {
  if (extendType == ARM64_EXT_INVALID && shift == 0) {
    // Special case: an invalid shift type with a shift amount of 0 implies an
    // identity operation
    return value;
  }

  uint64_t extended;
  switch (extendType) {
    case ARM64_EXT_UXTB:
      extended = static_cast<uint8_t>(value);
      break;
    case ARM64_EXT_UXTH:
      extended = static_cast<uint16_t>(value);
      break;
    case ARM64_EXT_UXTW:
      extended = static_cast<uint32_t>(value);
      break;
    case ARM64_EXT_UXTX:
      extended = value;
      break;
    case ARM64_EXT_SXTB:
      extended = static_cast<int8_t>(value);
      break;
    case ARM64_EXT_SXTH:
      extended = static_cast<int16_t>(value);
      break;
    case ARM64_EXT_SXTW:
      extended = static_cast<int32_t>(value);
      break;
    case ARM64_EXT_SXTX:
      extended = value;
      break;
    default:
      assert(false && "Invalid extension type");
      return 0;
  }

  return extended << shift;
}

/** Extend `value` using extension/shifting rules defined in `op`. */
inline uint64_t extendOffset(uint64_t value, const cs_arm64_op& op) {
  if (op.ext == 0) {
    if (op.shift.value == 0) {
      return value;
    }
    if (op.shift.type == 1) {
      return extendValue(value, ARM64_EXT_UXTX, op.shift.value);
    }
  }
  return extendValue(value, op.ext, op.shift.value);
}

/** Calculate the corresponding NZCV values from select SVE instructions that
 * set the First(N), None(Z), !Last(C) condition flags based on the predicate
 * result, and the V flag to 0. */
inline uint8_t getNZCVfromPred(std::array<uint64_t, 4> predResult,
                               uint64_t VL_bits, int byteCount) {
  uint8_t N = (predResult[0] & 1);
  uint8_t Z = 1;
  // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
  // predicate register we're working in. 1ull << (VL_bits / 8) - byteCount)
  // derives a 1 in the last position of the current predicate. Both
  // dictated by vector length.
  uint8_t C = !(predResult[(int)((VL_bits - 1) / 512)] &
                1ull << (((VL_bits / 8) - byteCount) % 64));
  for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
    if (predResult[i]) {
      Z = 0;
      break;
    }
  }
  return nzcv(N, Z, C, 0);
}

/** Multiply `a` and `b`, and return the high 64 bits of the result.
 * https://stackoverflow.com/a/28904636 */
inline uint64_t mulhi(uint64_t a, uint64_t b) {
  uint64_t a_lo = (uint32_t)a;
  uint64_t a_hi = a >> 32;
  uint64_t b_lo = (uint32_t)b;
  uint64_t b_hi = b >> 32;

  uint64_t a_x_b_hi = a_hi * b_hi;
  uint64_t a_x_b_mid = a_hi * b_lo;
  uint64_t b_x_a_mid = b_hi * a_lo;
  uint64_t a_x_b_lo = a_lo * b_lo;

  uint64_t carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                        (uint64_t)(uint32_t)b_x_a_mid + (a_x_b_lo >> 32)) >>
                       32;

  uint64_t multhi =
      a_x_b_hi + (a_x_b_mid >> 32) + (b_x_a_mid >> 32) + carry_bit;

  return multhi;
}

/** Decode the instruction pattern from sourceValuestr. */
inline uint16_t sveGetPattern(const std::string sourceValuestr,
                              const uint8_t esize, const uint16_t VL_) {
  const uint16_t elements = VL_ / esize;
  const std::vector<std::string> patterns = {
      "pow2", "vl1",  "vl2",  "vl3",   "vl4",   "vl5",  "vl6",  "vl7", "vl8",
      "vl16", "vl32", "vl64", "vl128", "vl256", "mul3", "mul4", "all"};

  // If no pattern present in sourceValuestr then same behaviour as ALL
  std::string pattern = "all";
  for (uint8_t i = 0; i < patterns.size(); i++) {
    if (sourceValuestr.find(patterns[i]) != std::string::npos) {
      pattern = patterns[i];
      // Don't break when pattern found as vl1 will be found in vl128 etc
    }
  }

  if (pattern == "all")
    return elements;
  else if (pattern == "pow2") {
    int n = 1;
    while (elements >= std::pow(2, n)) {
      n = n + 1;
    }
    return std::pow(2, n - 1);
  } else if (pattern == "vl1")
    return (elements >= 1) ? 1 : 0;
  else if (pattern == "vl2")
    return (elements >= 2) ? 2 : 0;
  else if (pattern == "vl3")
    return (elements >= 3) ? 3 : 0;
  else if (pattern == "vl4")
    return (elements >= 4) ? 4 : 0;
  else if (pattern == "vl5")
    return (elements >= 5) ? 5 : 0;
  else if (pattern == "vl6")
    return (elements >= 6) ? 6 : 0;
  else if (pattern == "vl7")
    return (elements >= 7) ? 7 : 0;
  else if (pattern == "vl8")
    return (elements >= 8) ? 8 : 0;
  else if (pattern == "vl16")
    return (elements >= 16) ? 16 : 0;
  else if (pattern == "vl32")
    return (elements >= 32) ? 32 : 0;
  else if (pattern == "vl64")
    return (elements >= 64) ? 64 : 0;
  else if (pattern == "vl128")
    return (elements >= 128) ? 128 : 0;
  else if (pattern == "vl256")
    return (elements >= 256) ? 256 : 0;
  else if (pattern == "mul4")
    return elements - (elements % 4);
  else if (pattern == "mul3")
    return elements - (elements % 3);

  return 0;
}

/** Apply the shift specified by `shiftType` to the unsigned integer `value`,
 * shifting by `amount`. */
template <typename T>
inline std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T>
shiftValue(T value, uint8_t shiftType, uint8_t amount) {
  switch (shiftType) {
    case ARM64_SFT_LSL:
      return value << amount;
    case ARM64_SFT_LSR:
      return value >> amount;
    case ARM64_SFT_ASR:
      return static_cast<std::make_signed_t<T>>(value) >> amount;
    case ARM64_SFT_ROR: {
      // Assuming sizeof(T) is a power of 2.
      const T mask = sizeof(T) * 8 - 1;
      assert((amount <= mask) && "Rotate amount exceeds type width");
      amount &= mask;
      return (value >> amount) | (value << ((-amount) & mask));
    }
    case ARM64_SFT_MSL: {
      // pad in with ones instead of zeros
      const T mask = (static_cast<T>(1) << static_cast<T>(amount)) - 1;
      return (value << amount) | mask;
    }
    case ARM64_SFT_INVALID:
      return value;
    default:
      assert(false && "Unknown shift type");
      return 0;
  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng