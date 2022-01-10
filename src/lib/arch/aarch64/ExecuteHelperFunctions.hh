#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class InstrExecFunc {
 public:
  /** Returns a correctly formatted nzcv value. */
  uint8_t nzcv(bool n, bool z, bool c, bool v) {
    return (n << 3) | (z << 2) | (c << 1) | v;
  }

  /** Calculate the corresponding NZCV values from select SVE instructions that
   * set the First(N), None(Z), !Last(C) condition flags based on the predicate
   * result, and the V flag to 0. */
  uint8_t getNZCVfromPred(uint64_t* predResult, uint64_t VL_bits,
                          int byteCount) {
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

  /** Manipulate the bitfield `value` according to the logic of the (U|S)BFM
   * ARMv8 instructions. */
  template <typename T>
  std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T>
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

  /** Performs a type agnostic add with carry. */
  template <typename T>
  std::tuple<T, uint8_t> addWithCarry(T x, T y, bool carryIn) {
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

  /** Multiply `a` and `b`, and return the high 64 bits of the result.
   * https://stackoverflow.com/a/28904636 */
  uint64_t mulhi(uint64_t a, uint64_t b) {
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

  /** Function to check if NZCV conditions hold. */
  bool conditionHolds(uint8_t cond, uint8_t nzcv) {
    if (cond == 0b1111) {
      return true;
    }

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
        result = true;
    }

    return (inverse ? !result : result);
  }

  // Rounding function that rounds a double to nearest integer (64-bit). In
  // event of a tie (i.e. 7.5) it will be rounded to the nearest even number.
  int64_t doubleRoundToNearestTiesToEven(double input) {
    if (std::fabs(input - std::trunc(input)) == 0.5) {
      if (static_cast<int64_t>(input - 0.5) % 2 == 0) {
        return static_cast<int64_t>(input - 0.5);
      } else {
        return static_cast<int64_t>(input + 0.5);
      }
    }
    // Otherwise round to nearest
    return static_cast<int64_t>(std::round(input));
  }

  // Rounding function that rounds a float to nearest integer (32-bit). In event
  // of a tie (i.e. 7.5) it will be rounded to the nearest even number.
  int32_t floatRoundToNearestTiesToEven(float input) {
    if (std::fabs(input - std::trunc(input)) == 0.5f) {
      if (static_cast<int32_t>(input - 0.5f) % 2 == 0) {
        return static_cast<int32_t>(input - 0.5f);
      } else {
        return static_cast<int32_t>(input + 0.5f);
      }
    }
    // Otherwise round to nearest
    return static_cast<int32_t>(std::round(input));
  }
  // --------------------------------------------------------------------------
  // --------------- INSTRUCTION EXECUTE HELPER FUNCTIONS BELOW ---------------
  // --------------------------------------------------------------------------

  /** Helper function for NEON instructions with the format `add vd, vn, vm`. */
  template <typename T, int I>
  static std::array<T, (16 / sizeof(T))> vecAdd_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const T* n = operands[0].getAsVector<T>();
    const T* m = operands[1].getAsVector<T>();
    std::array<T, (16 / sizeof(T))> out = {0};
    for (int i = 0; i < I; i++) {
      out[i] = static_cast<T>(n[i] + m[i]);
    }
    return out;
  }

  /** Helper function for instructions with the format `add rd, rn, rm`. */
  template <typename T>
  static T add_3ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands) {
    const T n = operands[0].get<T>();
    const T m = operands[1].get<T>();
    return (n + m);
  }

  /** Helper function for instructions with the format `movz {w,x}d, #imm`. */
  template <typename T>
  static T movz_imm(
      struct simeng::arch::aarch64::InstructionMetadata metadata) {
    uint8_t shift = metadata.operands[1].shift.value;
    T value = static_cast<uint64_t>(metadata.operands[1].imm) << shift;
    return value;
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng