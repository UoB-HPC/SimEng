#include <cmath>
#include <limits>
#include <tuple>

#include "InstructionMetadata.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

uint8_t nzcv(bool n, bool z, bool c, bool v) {
  return (n << 3) | (z << 2) | (c << 1) | v;
}

/** Apply the shift specified by `shiftType` to the unsigned integer `value`,
 * shifting by `amount`. */
template <typename T>
std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T> shiftValue(
    T value, uint8_t shiftType, uint8_t amount) {
  switch (shiftType) {
    case ARM64_SFT_LSL:
      return value << amount;
    case ARM64_SFT_LSR:
      return value >> amount;
    case ARM64_SFT_ASR:
      return static_cast<std::make_signed_t<T>>(value) >> amount;
    case ARM64_SFT_ROR: {
      auto highestBit = sizeof(T) * 8;
      return (value >> amount) & (value << (highestBit - amount));
    }
    case ARM64_SFT_INVALID:
      return value;
    default:
      assert(false && "Unknown shift type");
      return 0;
  }
}

/** Manipulate the bitfield `value` according to the logic of the (U|S)BFM ARMv8
 * instructions. */
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
  // Shift the bitfield up, and cast to a signed type, so the highest bit is now
  // the sign bit
  auto shifted = static_cast<std::make_signed_t<T>>(result << shiftAmount);
  // Shift the bitfield back to where it was; as it's a signed type, the
  // compiler will sign-extend the highest bit
  return shifted >> shiftAmount;
}

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
    // We know x + carryIn <= max, so can safely subtract and compare against y
    // max > x + y + c == max - x > y + c
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

void Instruction::executionNYI() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ExecutionNotYetImplemented;
  return;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  executed_ = true;
  switch (metadata.opcode) {
    case Opcode::AArch64_ADDv1i64: {  // add dd, dn, dm
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out[2] = {static_cast<uint64_t>(n + m), 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDv4i32: {  // add vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] + m[0]),
                         static_cast<uint32_t>(n[1] + m[1]),
                         static_cast<uint32_t>(n[2] + m[2]),
                         static_cast<uint32_t>(n[3] + m[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADCXr: {  // adc xd, xn, xm
      const uint8_t carry = operands[0].get<uint8_t>() & 0b0010;
      const uint64_t n = operands[1].get<uint64_t>();
      const uint64_t m = operands[2].get<uint64_t>();
      auto [result, nzcv] = addWithCarry(n, m, carry);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ADDPv16i8: {  // addp vd.16b, vn.16b, vm.16b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16] = {static_cast<uint8_t>(n[0] + n[1]),
                         static_cast<uint8_t>(n[2] + n[3]),
                         static_cast<uint8_t>(n[4] + n[5]),
                         static_cast<uint8_t>(n[6] + n[7]),
                         static_cast<uint8_t>(n[8] + n[9]),
                         static_cast<uint8_t>(n[10] + n[11]),
                         static_cast<uint8_t>(n[12] + n[13]),
                         static_cast<uint8_t>(n[14] + n[15]),
                         static_cast<uint8_t>(m[0] + m[1]),
                         static_cast<uint8_t>(m[2] + m[3]),
                         static_cast<uint8_t>(m[4] + m[5]),
                         static_cast<uint8_t>(m[6] + m[7]),
                         static_cast<uint8_t>(m[8] + m[9]),
                         static_cast<uint8_t>(m[10] + m[11]),
                         static_cast<uint8_t>(m[12] + m[13]),
                         static_cast<uint8_t>(m[14] + m[15])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDPv2i64: {  // addp vd.2d, vn.2d, vm.2d
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t* m = operands[1].getAsVector<uint64_t>();
      uint64_t out[2] = {n[0] + n[1], m[0] + m[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDPv2i64p: {  // addp dd, vn.2d
      const uint64_t* a = operands[0].getAsVector<uint64_t>();
      uint64_t out[2] = {a[0] + a[1], 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDPv4i32: {  // addp vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] + n[1], n[2] + n[3], m[0] + m[1], m[2] + m[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDPv8i16: {  // addp vd.8h, vn.8h, vm.8h
      const uint16_t* n = operands[0].getAsVector<uint16_t>();
      const uint16_t* m = operands[1].getAsVector<uint16_t>();
      uint16_t out[8] = {static_cast<uint16_t>(n[0] + n[1]),
                         static_cast<uint16_t>(n[2] + n[3]),
                         static_cast<uint16_t>(n[4] + n[5]),
                         static_cast<uint16_t>(n[6] + n[7]),
                         static_cast<uint16_t>(m[0] + m[1]),
                         static_cast<uint16_t>(m[2] + m[3]),
                         static_cast<uint16_t>(m[4] + m[5]),
                         static_cast<uint16_t>(m[6] + m[7])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDSWri: {  // adds wd, wn, #imm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSWrs: {  // adds wd, wn, wm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSWrx: {  // adds wd, wn, wm{, extend {#amount}}
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value));
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSXri: {  // adds xd, xn, #imm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDSXrs: {  // adds xd, xn, xm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDSXrx: {  // adds xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDSXrx64: {  // adds xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDVL_XXI: {  // addvl xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = static_cast<int64_t>(metadata.operands[2].imm);
      const uint64_t VL_bits = 512;
      // convert VL from LEN (number of 128-bits) to bytes
      const uint64_t VL = VL_bits / 8;
      results[0] = x + (VL * y);
      break;
    }
    case Opcode::AArch64_ADDVv8i8v: {  // addv bd, vn.8b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      uint8_t out[16] = {0};
      for (int i = 0; i < 8; i++) {
        out[0] += n[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ADDWri: {  // add wd, wn, #imm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x + y, 8);
      break;
    }
    case Opcode::AArch64_ADDWrs: {  // add wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(x + y);
      break;
    }
    case Opcode::AArch64_ADDWrx: {  // add wd, wn, wm{, extend #amount}
      auto x = operands[0].get<uint32_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x + y;
      break;
    }
    case Opcode::AArch64_ADDXri: {  // add xd, xn, #imm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x + y);
      break;
    }
    case Opcode::AArch64_ADDXrs: {  // add xd, xn, xm, {shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x + y;
      break;
    }
    case Opcode::AArch64_ADDXrx: {  // add xd, xn, wm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x + y;
      break;
    }
    case Opcode::AArch64_ADDXrx64: {  // add xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x + y;
      break;
    }
    case Opcode::AArch64_ADR: {  // adr xd, #imm
      results[0] = instructionAddress_ + metadata.operands[1].imm;
      break;
    }
    case Opcode::AArch64_ADRP: {  // adrp xd, #imm
      // Clear lowest 12 bits of address and add immediate (already shifted by
      // decoder)
      results[0] = (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
      break;
    }
    case Opcode::AArch64_ANDSWri: {  // ands wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      uint32_t result = x & y;
      results[0] = nzcv(result >> 31, result == 0, false, false);
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ANDSWrs: {  // ands wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      uint32_t result = x & y;
      results[0] = nzcv(result >> 31, result == 0, false, false);
      if (destinationRegisterCount > 1) {
        results[1] = static_cast<uint64_t>(result);
      }
      break;
    }
    case Opcode::AArch64_ANDSXri: {  // ands xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      uint64_t result = x & y;
      results[0] = nzcv(result >> 63, result == 0, false, false);
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ANDSXrs: {  // ands xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      uint64_t result = x & y;
      results[0] = nzcv(result >> 63, result == 0, false, false);
      if (destinationRegisterCount > 1) {
        results[1] = result;
      }
      break;
    }
    case Opcode::AArch64_ANDWri: {  // and wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      uint32_t result = x & y;
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ANDWrs: {  // and wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(x & y);
      break;
    }
    case Opcode::AArch64_ANDXri: {  // and xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      results[0] = x & y;
      break;
    }
    case Opcode::AArch64_ANDXrs: {  // and xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x & y;
      break;
    }
    case Opcode::AArch64_AND_PPzPP: {  // and pd.b, pg/z, pn.b, pm.b
      const uint64_t* g = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      // Divide by 512 as we're operating in blocks of 64-bits
      // and each predicate bit represents 8 bits in Z registers or
      // more generally the VL notion.
      const uint16_t partition_num = VL_bits / 512;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        // AND the two source registers in blocks of 64-bits with
        // the governing predicate as a mask.
        out[i] = g[i] & (n[i] & m[i]);
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_ANDv16i8: {  // and vd.16b, vn.16b, vm.16b
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t* m = operands[1].getAsVector<uint64_t>();
      uint64_t out[2] = {n[0] & m[0], n[1] & m[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ANDv8i8: {  // and vd.8b, vn.8b, vm.8b
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] & m[0], n[1] & m[1], 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ASRVWr: {  // asrv wd, wn, wm
      auto n = operands[0].get<int32_t>();
      auto m = operands[1].get<uint32_t>();
      results[0] = RegisterValue(n >> (m % 32), 8);
      break;
    }
    case Opcode::AArch64_ASRVXr: {  // asrv xd, xn, xm
      auto n = operands[0].get<int64_t>();
      auto m = operands[1].get<uint64_t>();
      results[0] = n >> (m % 64);
      break;
    }
    case Opcode::AArch64_B: {  // b label
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      break;
    }
    case Opcode::AArch64_BFMWri: {  // bfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t dest = operands[0].get<uint32_t>();
      uint32_t source = operands[1].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, dest, r, s), 8);
      break;
    }
    case Opcode::AArch64_BFMXri: {  // bfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t dest = operands[0].get<uint64_t>();
      uint64_t source = operands[1].get<uint64_t>();
      results[0] = bitfieldManipulate(source, dest, r, s);
      break;
    }
    case Opcode::AArch64_BICWrs: {  // bic wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = RegisterValue(x & y, 8);
      break;
    }
    case Opcode::AArch64_BICXrs: {  // bic xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = x & y;
      break;
    }
    case Opcode::AArch64_BICSWrs: {  // bics wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto result = x & y;
      bool n = (static_cast<int32_t>(result) < 0);
      bool z = (result == 0);
      results[0] = nzcv(n, z, false, false);
      results[1] = RegisterValue(x & y, 8);
      break;
    }
    case Opcode::AArch64_BICSXrs: {  // bics xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto result = x & y;
      bool n = (static_cast<int64_t>(result) < 0);
      bool z = (result == 0);
      results[0] = nzcv(n, z, false, false);
      results[1] = result;
      break;
    }
    case Opcode::AArch64_BICv16i8: {  // bic vd.16b, vn.16b, vm.16b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = n[i] & ~m[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_BICv4i32: {  // bic vd.4s, #imm{, lsl #shift}
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      uint32_t imm = ~shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t out[4] = {d[0] & imm, d[1] & imm, d[2] & imm, d[3] & imm};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_BICv8i8: {  // bic vd.8b, vn.8b, vm.8b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      for (int i = 0; i < 8; i++) {
        out[i] = n[i] & ~m[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_Bcc: {  // b.cond label
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_BIFv16i8: {  // bif vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      uint64_t out[2] = {(d[0] & m[0]) | (n[0] & ~m[0]),
                         (d[1] & m[1]) | (n[1] & ~m[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_BITv16i8: {  // bit vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      uint64_t out[2] = {(d[0] & ~m[0]) | (n[0] & m[0]),
                         (d[1] & ~m[1]) | (n[1] & m[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_BL: {  // bl #imm
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      break;
    }
    case Opcode::AArch64_BR: {  // br xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      break;
    }
    case Opcode::AArch64_BLR: {  // blr xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      break;
    }
    case Opcode::AArch64_BSLv16i8: {  // bsl vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      uint64_t out[2] = {(d[0] & n[0]) | ((~d[0]) & m[0]),
                         (d[1] & n[1]) | ((~d[1]) & m[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CBNZW: {  // cbnz wn, #imm
      if (operands[0].get<uint32_t>() == 0) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      }
      break;
    }
    case Opcode::AArch64_CBNZX: {  // cbnz xn, #imm
      if (operands[0].get<uint64_t>() == 0) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      }
      break;
    }
    case Opcode::AArch64_CBZW: {  // cbz wn, #imm
      if (operands[0].get<uint32_t>() == 0) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_CBZX: {  // cbz xn, #imm
      if (operands[0].get<uint64_t>() == 0) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_CCMNWi: {  // ccmn wn, #imm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) =
            addWithCarry(operands[1].get<uint32_t>(),
                         static_cast<uint32_t>(metadata.operands[1].imm), 0);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CCMNXi: {  // ccmn xn, #imm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) =
            addWithCarry(operands[1].get<uint64_t>(),
                         static_cast<uint64_t>(metadata.operands[1].imm), 0);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CCMPWi: {  // ccmp wn, #imm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) =
            addWithCarry(operands[1].get<uint32_t>(),
                         ~static_cast<uint32_t>(metadata.operands[1].imm), 1);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CCMPWr: {  // ccmp wn, wm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) = addWithCarry(
            operands[1].get<uint32_t>(), ~operands[2].get<uint32_t>(), 1);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CCMPXi: {  // ccmp xn, #imm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) =
            addWithCarry(operands[1].get<uint64_t>(),
                         ~static_cast<uint64_t>(metadata.operands[1].imm), 1);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CCMPXr: {  // ccmp xn, xm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        uint8_t nzcv;
        std::tie(std::ignore, nzcv) = addWithCarry(
            operands[1].get<uint64_t>(), ~operands[2].get<uint64_t>(), 1);
        results[0] = nzcv;
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_CLZXr: {  // clz xd, xn
      auto x = operands[0].get<int64_t>();
      uint64_t i;
      for (i = 0; i < 64; i++) {
        // Left-shift x until it's negative or we run out of bits
        if (x < 0) {
          break;
        }
        x <<= 1;
      }

      results[0] = i;
      break;
    }
    case Opcode::AArch64_CMEQv16i8: {  // cmeq vd.16b, vn.16b, vm.16b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = (n[i] == m[i]) ? 0xFF : 0;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CMEQv16i8rz: {  // cmeq vd.16b, vn.16b, #0
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = (n[i] == 0) ? 0xFF : 0;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CMHIv4i32: {  // cmhi vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4];
      for (int i = 0; i < 4; i++) {
        out[i] = (n[i] > m[i]) ? 0xFFFFFFFF : 0;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZI_S: {  // cmpne pd.s, pg/z. zn.s, #imm
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const int32_t* n = operands[1].getAsVector<int32_t>();
      const int8_t m = static_cast<int8_t>(metadata.operands[3].imm);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 16] & (uint64_t)std::pow(2, ((i % 16) * 4));
        if (shifted_active) {
          out[i / 16] =
              (n[i] != m) ? (out[i / 16] | shifted_active) : out[i / 16];
        }
      }

      uint8_t N = (out[0] & 1);
      uint8_t Z = 1;
      // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
      // predicate register we're working in. std::pow(2, (VL_bits / 8) - 1)
      // derives a 1 in the last position of the current predicate. Both
      // dictated by vector length.
      uint8_t C =
          !(out[(int)((VL_bits - 1) / 512)] & (uint64_t)std::pow(2, 64 - 4));
      for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
        if (out[i]) {
          Z = 0;
          break;
        }
      }
      results[0] = nzcv(N, Z, C, 0);
      results[1] = out;
      break;
    }
    case Opcode::AArch64_CNTB_XPiI: {  // cntb xd{, pattern{, #imm}}
      const uint64_t VL_bits = 512;
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = (VL_bits / 8) * imm;
      break;
    }
    case Opcode::AArch64_CNTH_XPiI: {  // cnth xd{, pattern{, #imm}}
      const uint64_t VL_bits = 512;
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = (VL_bits / 16) * imm;
      break;
    }
    case Opcode::AArch64_CNTW_XPiI: {  // cntw xd{, pattern{, #imm}}
      const uint64_t VL_bits = 512;
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = (VL_bits / 32) * imm;
      break;
    }
    case Opcode::AArch64_CNTv8i8: {  // cnt vd.8b, vn.8b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      uint8_t out[16] = {0};
      for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
          // Move queried bit to LSB and extract via an AND operator
          out[i] += ((n[i] >> j) & 1);
        }
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CPYi32: {  // dup vd, vn.s[index]
      const uint32_t* vec = operands[0].getAsVector<uint32_t>();
      uint32_t out[4] = {vec[metadata.operands[1].vector_index], 0, 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CPYi64: {  // dup vd, vn.d[index]
      const uint64_t* vec = operands[0].getAsVector<uint64_t>();
      uint64_t out[2] = {vec[metadata.operands[1].vector_index], 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_CSELWr: {  // csel wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = static_cast<uint64_t>(operands[1].get<uint32_t>());
      } else {
        results[0] = static_cast<uint64_t>(operands[2].get<uint32_t>());
      }
      break;
    }
    case Opcode::AArch64_CSELXr: {  // csel xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = operands[2].get<uint64_t>();
      }
      break;
    }
    case Opcode::AArch64_CSNEGWr: {  // csneg wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = static_cast<int64_t>(operands[1].get<int32_t>());
      } else {
        results[0] = static_cast<int64_t>(-operands[2].get<int32_t>());
      }
      break;
    }
    case Opcode::AArch64_CSNEGXr: {  // csneg xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<int64_t>();
      } else {
        results[0] = -operands[2].get<int64_t>();
      }
      break;
    }
    case Opcode::AArch64_CSINCWr: {  // csinc wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = RegisterValue(operands[1].get<uint32_t>(), 8);
      } else {
        results[0] = RegisterValue(operands[2].get<uint32_t>() + 1, 8);
      }
      break;
    }
    case Opcode::AArch64_CSINCXr: {  // csinc xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = operands[2].get<uint64_t>() + 1;
      }
      break;
    }
    case Opcode::AArch64_CSINVWr: {  // csinv wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = RegisterValue(operands[1].get<uint32_t>(), 8);
      } else {
        results[0] = RegisterValue(~operands[2].get<uint32_t>(), 8);
      }
      break;
    }
    case Opcode::AArch64_CSINVXr: {  // csinv xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = ~operands[2].get<uint64_t>();
      }
      break;
    }
    case Opcode::AArch64_DECB_XPiI: {  // decb xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t VL_bits = 512;
      results[0] = n - (VL_bits / 8);
      break;
    }
    case Opcode::AArch64_DUPM_ZI: {  // dupm zd.t, #imm
      const uint64_t VL_bits = 512;
      const uint64_t imm = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t out[32] = {0};
      for (int i = 0; i < (VL_bits / 64); i++) {
        out[i] = imm;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUP_ZI_B: {  // dup zd.b, #imm{, shift}
      const int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      int8_t out[256] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = imm;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUP_ZI_D: {  // dup zd.d, #imm{, shift}
      const int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      int64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = imm;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUP_ZI_S: {  // dup zd.s, #imm{, shift}
      const int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = imm;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUP_ZR_S: {  // dup zd.s, wn
      const int32_t n = operands[0].get<uint32_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUP_ZZI_D: {  // dup zd.d, zn.d[#imm]
      const uint8_t index =
          static_cast<uint8_t>(metadata.operands[1].vector_index);
      const uint64_t* n = operands[0].getAsVector<uint64_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};

      if (index < (VL_bits / 64)) {
        const uint64_t element = n[index];
        for (int i = 0; i < partition_num; i++) {
          out[i] = element;
        }
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_DUP_ZZI_S: {  // dup zd.s, zn.s[#imm]
      const uint8_t index =
          static_cast<uint8_t>(metadata.operands[1].vector_index);
      const uint32_t* n = operands[0].getAsVector<uint32_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint32_t out[64] = {0};

      if (index < (VL_bits / 32)) {
        const uint32_t element = n[index];
        for (int i = 0; i < partition_num; i++) {
          out[i] = element;
        }
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_DUPv16i8gpr: {  // dup vd.16b, wn
      uint8_t out[16];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint8_t>());
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv2i32gpr: {  // dup vd.2s, wn
      uint32_t element = operands[0].get<uint32_t>();
      uint32_t out[4] = {element, element, 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv2i32lane: {  // dup vd.2s, vn.s[index]
      int index = metadata.operands[1].vector_index;
      uint32_t element = operands[0].getAsVector<uint32_t>()[index];
      uint32_t out[4] = {element, element, 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv2i64gpr: {  // dup vd.2d, xn
      uint64_t out[2];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint64_t>());
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv2i64lane: {  // dup vd.2d, vn.d[index]
      int index = metadata.operands[1].vector_index;
      uint64_t element = operands[0].getAsVector<uint64_t>()[index];
      uint64_t out[2];
      std::fill(std::begin(out), std::end(out), element);
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv4i16gpr: {  // dup vd.4h, wn
      uint16_t element = operands[0].get<uint16_t>();
      uint16_t out[8] = {element, element, element, element, 0, 0, 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv4i32gpr: {  // dup vd.4s, wn
      uint32_t out[4];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint32_t>());
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DUPv4i32lane: {  // dup vd.4s, vn.s[index]
      int index = metadata.operands[1].vector_index;
      uint32_t element = operands[0].getAsVector<uint32_t>()[index];
      uint32_t out[4];
      std::fill(std::begin(out), std::end(out), element);
      results[0] = out;
      break;
    }
    case Opcode::AArch64_DMB: {  // dmb option|#imm
      // TODO: Respect memory barriers
      break;
    }
    case Opcode::AArch64_EORWri: {  // eor wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      results[0] = RegisterValue(x ^ y, 8);
      break;
    }
    case Opcode::AArch64_EORWrs: {  // eor wd, wn, wm{, shift #imm}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x ^ y, 8);
      break;
    }
    case Opcode::AArch64_EORXri: {  // eor xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = static_cast<uint64_t>(metadata.operands[2].imm);
      results[0] = x ^ y;
      break;
    }
    case Opcode::AArch64_EORXrs: {  // eor xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x ^ y;
      break;
    }
    case Opcode::AArch64_EORv16i8: {  // eor vd.16b, vn.16b, vm.16b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = n[i] ^ m[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_EXTRWrri: {  // extr wd, wn, wm, #lsb
      uint32_t n = operands[0].get<uint32_t>();
      uint32_t m = operands[1].get<uint32_t>();
      int64_t lsb = metadata.operands[3].imm;
      if (lsb == 0) {
        results[0] = RegisterValue(m, 8);
      } else {
        results[0] = RegisterValue((m >> lsb) | (n << (32 - lsb)), 8);
      }
      break;
    }
    case Opcode::AArch64_EXTRXrri: {  // extr xd, xn, xm, #lsb
      uint64_t n = operands[0].get<uint64_t>();
      uint64_t m = operands[1].get<uint64_t>();
      int64_t lsb = metadata.operands[3].imm;
      if (lsb == 0) {
        results[0] = m;
      } else {
        results[0] = (m >> lsb) | (n << (64 - lsb));
      }
      break;
    }
    case Opcode::AArch64_FABD32: {  // fabd sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {std::fabs(n - m), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABD64: {  // fabd dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {std::fabs(n - m), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABSDr: {  // fabs dd, dn
      double n = operands[0].get<double>();
      double out[2] = {std::fabs(n), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABSSr: {  // fabs sd, sn
      float n = operands[0].get<float>();
      float out[4] = {std::fabs(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABS_ZPmZ_S: {  // fabs zd.s, pg/m, zn.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = ::fabs(n[i]);
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABSv2f64: {  // fabs vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fabs(n[0]), std::fabs(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FABSv4f32: {  // fabs vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {std::fabs(n[0]), std::fabs(n[1]), std::fabs(n[2]),
                      std::fabs(n[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDA_VPZ_D: {  // fadda dd, pg/m, dn, zm.d
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const double* m = operands[3].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[2] = {operands[2].get<double>(), 0.0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[0] += m[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDDrr: {  // fadd dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n + m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDSrr: {  // fadd sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n + m, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] + b[0], a[1] + b[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDv4f32: {  // fadd vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      float out[4] = {a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDPv2i64p: {  // faddp dd, vn.2d
      const double* a = operands[0].getAsVector<double>();
      double out[2] = {a[0] + a[1], 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDPv4f32: {  // faddp vd.4s, vn.4s, vm.4s
      // swap the order of operands to have correct behaviour
      const float* n = operands[1].getAsVector<float>();
      const float* m = operands[0].getAsVector<float>();
      float concat[8];
      float out[4];
      for (int i = 0; i < 4; i++) {
        concat[i] = m[i];
        concat[i + 4] = n[i];
      }
      for (int i = 0; i < 4; i++) {
        out[i] = concat[2 * i] + concat[2 * i + 1];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDPv2f32: {  // faddp vd.2s, vn.2s, vm.2s
      // swap the order of operands to have correct behaviour
      const float* n = operands[1].getAsVector<float>();
      const float* m = operands[0].getAsVector<float>();
      float concat[4];
      float out[4] = {0.f, 0.f, 0.f, 0.f};
      for (int i = 0; i < 2; i++) {
        concat[i] = m[i];
        concat[i + 2] = n[i];
      }
      for (int i = 0; i < 2; i++) {
        out[i] = concat[2 * i] + concat[2 * i + 1];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDPv2f64: {  // faddp vd.2d, vn.2d, vm.2d
      // swap the order of operands to have correct behaviour
      const double* n = operands[1].getAsVector<double>();
      const double* m = operands[0].getAsVector<double>();
      double concat[4];
      double out[2];
      for (int i = 0; i < 2; i++) {
        concat[i] = m[i];
        concat[i + 2] = n[i];
      }
      for (int i = 0; i < 2; i++) {
        out[i] = concat[2 * i] + concat[2 * i + 1];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADDPv8f16:  // faddp vd.8h, vn.8h, vm.8h
      [[fallthrough]];
    case Opcode::AArch64_FADDPv4f16: {  // faddp vd.4h, vn.4h, vm.4h
      executionNYI();
      break;
    }
    case Opcode::AArch64_FADD_ZPmZ_D: {  // fadd zdn.d, pg/m, zdn.d, zm.d
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* b = operands[1].getAsVector<double>();
      const double* c = operands[2].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = b[i] + c[i];
        } else {
          out[i] = b[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADD_ZZZ_D: {  // fadd zd.d, zn.d, zm.d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] + m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FADD_ZZZ_S: {  // fadd zd.s, zn.s, zm.s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] + m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCCMPDrr:     // fccmp sn, sm, #nzcv, cc
    case Opcode::AArch64_FCCMPEDrr: {  // fccmpe sn, sm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        double a = operands[1].get<double>();
        double b = operands[2].get<double>();
        if (std::isnan(a) || std::isnan(b)) {
          // TODO: Raise exception if NaNs are signalling or fcmpe
          results[0] = nzcv(false, false, true, true);
        } else if (a == b) {
          results[0] = nzcv(false, true, true, false);
        } else if (a < b) {
          results[0] = nzcv(true, false, false, false);
        } else {
          results[0] = nzcv(false, false, true, false);
        }
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_FCCMPSrr:     // fccmp sn, sm, #nzcv, cc
    case Opcode::AArch64_FCCMPESrr: {  // fccmpe sn, sm, #nzcv, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        float a = operands[1].get<float>();
        float b = operands[2].get<float>();
        if (std::isnan(a) || std::isnan(b)) {
          // TODO: Raise exception if NaNs are signalling or fcmpe
          results[0] = nzcv(false, false, true, true);
        } else if (a == b) {
          results[0] = nzcv(false, true, true, false);
        } else if (a < b) {
          results[0] = nzcv(true, false, false, false);
        } else {
          results[0] = nzcv(false, false, true, false);
        }
      } else {
        results[0] = static_cast<uint8_t>(metadata.operands[2].imm);
      }
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZ0_D: {  // fcmge pd.d, pg/z, zn.d, #0.0
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* n = operands[1].getAsVector<double>();
      const double m = static_cast<double>(metadata.operands[3].fp);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 8] & (uint64_t)std::pow(2, ((i % 8) * 8));
        if (shifted_active) {
          out[i / 8] = (n[i] >= m) ? (out[i / 8] | shifted_active) : out[i / 8];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZ0_S: {  // fcmge pd.s, pg/z, zn.s, #0.0
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();
      const float m = static_cast<float>(metadata.operands[3].fp);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 16] & (uint64_t)std::pow(2, ((i % 16) * 4));
        if (shifted_active) {
          out[i / 16] =
              (n[i] >= m) ? (out[i / 16] | shifted_active) : out[i / 16];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGEv2i64rz: {  // fcmge vd.2d, vn.2d, 0.0
      const double* n = operands[0].getAsVector<double>();
      uint64_t out[2] = {static_cast<uint64_t>(n[0] >= 0.0 ? -1 : 0),
                         static_cast<uint64_t>(n[1] >= 0.0 ? -1 : 0)};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGEv4i32rz: {  // fcmge vd.4s, vn.4s, 0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[1] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[2] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[3] >= 0.0 ? -1 : 0)};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZZ_D: {  // fcmgt pd.d, pg/z, zn.d, zm.d
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* n = operands[1].getAsVector<double>();
      const double* m = operands[2].getAsVector<double>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 8] & (uint64_t)std::pow(2, ((i % 8) * 8));
        if (shifted_active) {
          out[i / 8] =
              (n[i] > m[i]) ? (out[i / 8] | shifted_active) : out[i / 8];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZZ_S: {  // fcmgt pd.s, pg/z, zn.s, zm.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();
      const float* m = operands[2].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 16] & (uint64_t)std::pow(2, ((i % 16) * 4));
        if (shifted_active) {
          out[i / 16] =
              (n[i] > m[i]) ? (out[i / 16] | shifted_active) : out[i / 16];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMGTv4f32: {  // fcmgt vd.4s, vn.4s, vm.4s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] > m[0] ? -1 : 0),
                         static_cast<uint32_t>(n[1] > m[1] ? -1 : 0),
                         static_cast<uint32_t>(n[2] > m[2] ? -1 : 0),
                         static_cast<uint32_t>(n[3] > m[3] ? -1 : 0)};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMLT_PPzZ0_S: {  // fcmlt pd.s, pg/z, zn.s, #0.0
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();
      const float m = static_cast<float>(metadata.operands[3].fp);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active =
            p[i / 16] & (uint64_t)std::pow(2, ((i % 16) * 4));
        if (shifted_active) {
          out[i / 16] =
              (n[i] < m) ? (out[i / 16] | shifted_active) : out[i / 16];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMLTv4i32rz: {  // fcmlt vd.4s, vn.4s, #0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[1] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[2] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[3] < 0.0 ? -1 : 0)};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMPDri:     // fcmp dn, #imm
    case Opcode::AArch64_FCMPEDri: {  // fcmpe dn, #imm
      double a = operands[0].get<double>();
      double b = metadata.operands[1].fp;
      if (std::isnan(a) || std::isnan(b)) {
        // TODO: Raise exception if NaNs are signalling or fcmpe
        results[0] = nzcv(false, false, true, true);
      } else if (a == b) {
        results[0] = nzcv(false, true, true, false);
      } else if (a < b) {
        results[0] = nzcv(true, false, false, false);
      } else {
        results[0] = nzcv(false, false, true, false);
      }
      break;
    }
    case Opcode::AArch64_FCMPDrr:     // fcmp dn, dm
    case Opcode::AArch64_FCMPEDrr: {  // fcmpe dn, dm
      double a = operands[0].get<double>();
      double b = operands[1].get<double>();
      if (std::isnan(a) || std::isnan(b)) {
        // TODO: Raise exception if NaNs are signalling or fcmpe
        results[0] = nzcv(false, false, true, true);
      } else if (a == b) {
        results[0] = nzcv(false, true, true, false);
      } else if (a < b) {
        results[0] = nzcv(true, false, false, false);
      } else {
        results[0] = nzcv(false, false, true, false);
      }
      break;
    }
    case Opcode::AArch64_FCMPSri:     // fcmp sn, #imm
    case Opcode::AArch64_FCMPESri: {  // fcmpe sn, #imm
      float a = operands[0].get<float>();
      float b = metadata.operands[1].fp;
      if (std::isnan(a) || std::isnan(b)) {
        // TODO: Raise exception if NaNs are signalling or fcmpe
        results[0] = nzcv(false, false, true, true);
      } else if (a == b) {
        results[0] = nzcv(false, true, true, false);
      } else if (a < b) {
        results[0] = nzcv(true, false, false, false);
      } else {
        results[0] = nzcv(false, false, true, false);
      }
      break;
    }
    case Opcode::AArch64_FCMPSrr:     // fcmp sn, sm
    case Opcode::AArch64_FCMPESrr: {  // fcmpe sn, sm
      float a = operands[0].get<float>();
      float b = operands[1].get<float>();
      if (std::isnan(a) || std::isnan(b)) {
        // TODO: Raise exception if NaNs are signalling or fcmpe
        results[0] = nzcv(false, false, true, true);
      } else if (a == b) {
        results[0] = nzcv(false, true, true, false);
      } else if (a < b) {
        results[0] = nzcv(true, false, false, false);
      } else {
        results[0] = nzcv(false, false, true, false);
      }
      break;
    }
    case Opcode::AArch64_FCMEQv2i32rz: {  // fcmeq vd.2s, vd.2s, #0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {0};
      for (int i = 0; i < 2; i++) {
        if (n[i] == 0.f) {
          out[i] = 0xffffffff;
        }
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCMEQv4i32rz: {  // fcmeq vd.4s vn.4s, #0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {0};
      for (int i = 0; i < 4; i++) {
        if (n[i] == 0.f) {
          out[i] = 0xffffffff;
        }
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCSELDrrr: {  // fcsel dd, dn, dm, cond
      double n = operands[1].get<double>();
      double m = operands[2].get<double>();
      double out[2] = {
          conditionHolds(metadata.cc, operands[0].get<uint8_t>()) ? n : m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCSELSrrr: {  // fcsel sd, sn, sm, cond
      float n = operands[1].get<float>();
      float m = operands[2].get<float>();
      float out[4] = {
          conditionHolds(metadata.cc, operands[0].get<uint8_t>()) ? n : m, 0.f,
          0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTASUWDr: {  // fcvtas wd, dn
      results[0] = RegisterValue(
          static_cast<int32_t>(round(operands[0].get<double>())), 8);
      break;
    }
    case Opcode::AArch64_FCVTASUXDr: {  // fcvtas xd, dn
      results[0] = static_cast<int64_t>(round(operands[0].get<double>()));
      break;
    }
    case Opcode::AArch64_FCVTDSr: {  // fcvt dd, sn
      // TODO: Handle NaNs, denorms, and saturation?
      double out[2] = {static_cast<double>(operands[0].get<float>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTLv2i32: {  // fcvtl vd.2d, vn.2s
      const float* n = operands[0].getAsVector<float>();
      double out[2] = {static_cast<double>(n[0]), static_cast<double>(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTLv4i32: {  // fcvtl2 vd.2d, vn.4s
      const float* n = operands[0].getAsVector<float>();
      double out[2] = {static_cast<double>(n[2]), static_cast<double>(n[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTNv2i32: {  // fcvtn vd.2s, vn.2d
      const double* n = operands[0].getAsVector<double>();
      float out[4] = {static_cast<float>(n[0]), static_cast<float>(n[1]), 0.f,
                      0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTNv4i32: {  // fcvtn2 vd.4s, vn.2d
      const double* n = operands[0].getAsVector<double>();
      float out[4] = {0.f, 0.f, static_cast<float>(n[0]),
                      static_cast<float>(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTSDr: {  // fcvt sd, dn
      // TODO: Handle NaNs, denorms, and saturation?
      float out[4] = {static_cast<float>(operands[0].get<double>()), 0.f, 0.f,
                      0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTZSUWDr: {  // fcvtzs wd, dn
      double n = operands[0].get<double>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZSUWSr: {  // fcvtzs wd, sn
      float n = operands[0].get<float>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_DtoS: {  // fcvtzs zd.s, pg/m, zn.d
      const int32_t* a = operands[0].getAsVector<int32_t>();

      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const double* b = operands[2].getAsVector<double>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          if (b[i] > 2147483647) {
            out[(2 * i)] = 2147483647;
          } else if (b[i] < -2147483648) {
            out[(2 * i)] = -2147483648;
          } else {
            out[(2 * i)] = static_cast<int32_t>(std::trunc(b[i]));
          }
          // 4294967295 = 0xFFFFFFFF
          out[(2 * i) + 1] = (b[i] < 0) ? 4294967295u : 0;
        } else {
          out[(2 * i)] = a[(2 * i)];
          out[(2 * i) + 1] = a[(2 * i) + 1];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FCVTZSv2f64: {  // fcvtzs vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      // TODO: Handle NaNs, denorms, and saturation
      int64_t out[2] = {static_cast<int64_t>(std::trunc(n[0])),
                        static_cast<int64_t>(std::trunc(n[1]))};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FDIVDrr: {  // fdiv dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n / m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FDIVSrr: {  // fdiv sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n / m, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FDIV_ZPmZ_D: {  // fdiv zd.d, pg/m, zn.d, zm.d
      const double* a = operands[0].getAsVector<double>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const double* b = operands[2].getAsVector<double>();
      const double* c = operands[3].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = b[i] / c[i];
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FDIVv2f64: {  // fdiv vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {n[0] / m[0], n[1] / m[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FDUP_ZI_D: {  // fdup zd.d, #imm
      const double imm = metadata.operands[1].fp;
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};
      for (int i = 0; i < partition_num; i++) {
        out[i] = imm;
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_FDUP_ZI_S: {  // fdup zd.s, #imm
      const float imm = metadata.operands[1].fp;
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = imm;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMADDDrrr: {  // fmadd dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(n, m, a), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMADDSrrr: {  // fmadd sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(n, m, a), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMAD_ZPmZZ_S: {  // fmad zd.s, pg/m, zn.s, zm.s
      const float* a = operands[0].getAsVector<float>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const float* b = operands[2].getAsVector<float>();
      const float* c = operands[3].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = c[i] + (a[i] * b[i]);
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMAXNMDrr: {  // fmaxnm dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {std::fmax(n, m), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMAXNMPv2i64p: {  // fmaxnmp dd vd.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fmax(n[0], n[1]), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMAXNMSrr: {  // fmaxnm sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {std::fmax(n, m), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMAXNMv2f64: {  // fmaxnm vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {std::fmax(n[0], m[0]), std::fmax(n[1], m[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMINNMDrr: {  // fminnm dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {std::fmin(n, m), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMINNMSrr: {  // fminnm sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {std::fmin(n, m), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMINNMv2f64: {  // fminnm vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {std::fmin(n[0], m[0]), std::fmin(n[1], m[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMINNMPv2i64p: {  // fminnmp dd vd.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fmin(n[0], n[1]), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLAv2f64: {  // fmla vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      const double* c = operands[2].getAsVector<double>();
      double out[2] = {a[0] + b[0] * c[0], a[1] + b[1] * c[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLAv4f32: {  // fmla vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      const float* c = operands[2].getAsVector<float>();
      float out[4] = {a[0] + b[0] * c[0], a[1] + b[1] * c[1],
                      a[2] + b[2] * c[2], a[3] + b[3] * c[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLAv4i32_indexed: {  // fmla vd.4s, vn.4s, vm.s[index]
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      int index = metadata.operands[2].vector_index;
      const float c = operands[2].getAsVector<float>()[index];
      float out[4] = {a[0] + b[0] * c, a[1] + b[1] * c, a[2] + b[2] * c,
                      a[3] + b[3] * c};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLA_ZPmZZ_D: {  // fmla zd.d, pg/m, zn.d, zm.d
      const double* a = operands[0].getAsVector<double>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const double* b = operands[2].getAsVector<double>();
      const double* c = operands[3].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = a[i] + (b[i] * c[i]);
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLA_ZPmZZ_S: {  // fmla zd.s, pg/m, zn.s, zm.s
      const float* a = operands[0].getAsVector<float>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const float* b = operands[2].getAsVector<float>();
      const float* c = operands[3].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = a[i] + (b[i] * c[i]);
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLSv2f64: {  // fmls vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      const double* c = operands[2].getAsVector<double>();
      double out[2] = {a[0] - (b[0] * c[0]), a[1] - (b[1] * c[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLSv4f32: {  // fmls vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      const float* c = operands[2].getAsVector<float>();
      float out[4] = {a[0] - b[0] * c[0], a[1] - b[1] * c[1],
                      a[2] - b[2] * c[2], a[3] - b[3] * c[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLSv4i32_indexed: {  // fmls vd.4s, vn.4s, vm.s[index]
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      int index = metadata.operands[2].vector_index;
      const float c = operands[2].getAsVector<float>()[index];
      float out[4] = {a[0] - b[0] * c, a[1] - b[1] * c, a[2] - b[2] * c,
                      a[3] - b[3] * c};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMLS_ZPmZZ_S: {  // fmls zd.s, pg/m, zn.s, zm.s
      const float* a = operands[0].getAsVector<float>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const float* b = operands[2].getAsVector<float>();
      const float* c = operands[3].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = a[i] + (-b[i] * c[i]);
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVDXHighr: {  // fmov xd, vn.d[1]
      results[0] = operands[0].getAsVector<double>()[1];
      break;
    }
    case Opcode::AArch64_FMOVDXr: {  // fmov xd, dn
      results[0] = operands[0].get<double>();
      break;
    }
    case Opcode::AArch64_FMOVDi: {  // fmov dn, #imm
      double out[2] = {metadata.operands[1].fp, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVDr: {  // fmov dd, dn
      double out[2] = {operands[0].get<double>(), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVSWr: {  // fmov wd, sn
      results[0] = RegisterValue(operands[0].get<float>(), 8);
      break;
    }
    case Opcode::AArch64_FMOVSi: {  // fmov sn, #imm
      float out[4] = {static_cast<float>(metadata.operands[1].fp), 0.f, 0.f,
                      0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVSr: {  // fmov sd, sn
      float out[4] = {operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVWSr: {  // fmov sd, wn
      float out[4] = {operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVXDHighr: {  // fmov vd.d[1], xn
      double out[2] = {operands[0].get<double>(), operands[1].get<double>()};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVXDr: {  // fmov dd, xn
      double out[2] = {operands[0].get<double>(), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVv2f64_ns: {  // fmov vd.2d, #imm
      double out[2] = {metadata.operands[1].fp, metadata.operands[1].fp};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVv2f32_ns: {  // fmov vd.2s, #imm
      float imm = static_cast<float>(metadata.operands[1].fp);
      float out[4] = {imm, imm, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMOVv4f32_ns: {  // fmov vd.4s, #imm
      float imm = static_cast<float>(metadata.operands[1].fp);
      float out[4] = {imm, imm, imm, imm};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMSUBDrrr: {  // fmsub dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(-n, m, a), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMSUBSrrr: {  // fmsub sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(-n, m, a), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMSB_ZPmZZ_S: {  // fmsb zd.s, pg/m, zn.s, zm.s
      const float* a = operands[0].getAsVector<float>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const float* b = operands[2].getAsVector<float>();
      const float* c = operands[3].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = c[i] + (-a[i] * b[i]);
        } else {
          out[i] = a[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULDrr: {  // fmul dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n * m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULSrr: {  // fmul sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n * m, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULv1i32_indexed: {  // fmul sd, sn, vm.s[index]
      int index = metadata.operands[2].vector_index;
      float n = operands[0].get<float>();
      float m = operands[1].getAsVector<float>()[index];
      float out[4] = {n * m, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULv1i64_indexed: {  // fmul dd, dn, vm.d[index]
      int index = metadata.operands[2].vector_index;
      double n = operands[0].get<double>();
      double m = operands[1].getAsVector<double>()[index];
      double out[2] = {n * m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULv2f64: {  // fmul vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] * b[0], a[1] * b[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULv4f32: {  // fmul vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      float out[4] = {a[0] * b[0], a[1] * b[1], a[2] * b[2], a[3] * b[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMULv4i32_indexed: {  // fmul vd.4s, vn.4s, vm.s[index]
      int index = metadata.operands[2].vector_index;
      const float* a = operands[0].getAsVector<float>();
      const float b = operands[1].getAsVector<float>()[index];
      float out[4] = {a[0] * b, a[1] * b, a[2] * b, a[3] * b};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZZZ_D: {  // fmul zd.d, zn.d, zm.d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] * m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZZZ_S: {  // fmul zd.s, zn.s, zm.s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] * m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZPmI_D: {  // fmul zd.d, pg/m, zn.d, #imm
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* n = operands[1].getAsVector<double>();
      const float fp = metadata.operands[3].fp;
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = n[i] * fp;
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZPmI_S: {  // fmul zd.s, pg/m, zn.s, #imm
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();
      const float fp = metadata.operands[3].fp;
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = n[i] * fp;
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZPmZ_D: {  // fmul zdn.d, pg/m, zdn.d, zm.d
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* n = operands[1].getAsVector<double>();
      const double* m = operands[2].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = n[i] * m[i];
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FMUL_ZPmZ_S: {  // fmul zdn.s, pg/m, zdn.s, zm.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();
      const float* m = operands[2].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = n[i] * m[i];
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEGDr: {  // fneg dd, dn
      double out[2] = {-operands[0].get<double>(), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEGSr: {  // fneg sd, sn
      float out[4] = {-operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEG_ZPmZ_D: {  // fneg zd.d, pg/m, zn.d
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const double* n = operands[1].getAsVector<double>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = -n[i];
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEG_ZPmZ_S: {  // fneg zd.s, pg/m, zn.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = -n[i];
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEGv2f64: {  // fneg vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {-n[0], -n[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNEGv4f32: {  // fneg vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {-n[0], -n[1], -n[2], -n[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNMSUBDrrr: {  // fnmsub dd, dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(n, m, -a), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNMSUBSrrr: {  // fnmsub sd, sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(n, m, -a), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNMULDrr: {  // fnmul dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {-(n * m), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FNMULSrr: {  // fnmul sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {-(n * m), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRINTADr: {  // frinta dd, dn
      double out[2] = {round(operands[0].get<double>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTEv1i32: {  // frsqrte sd, sn
      float n = operands[0].get<float>();
      float out[4] = {1.f / sqrtf(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTEv1i64: {  // frsqrte dd, dn
      double n = operands[0].get<double>();
      double out[2] = {1.0 / ::sqrt(n), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTEv2f32: {  // frsqrte vd.2s, vn.2s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {0.f, 0.f, 0.f, 0.f};
      for (int i = 0; i < 2; i++) {
        out[i] = 1.f / sqrtf(n[i]);
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTEv4f32: {  // frsqrte vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4];
      for (int i = 0; i < 4; i++) {
        out[i] = 1.f / ::sqrtf(n[i]);
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTEv2f64: {  // frsqrte vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = 1.0 / sqrt(n[i]);
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTS32: {  // frsqrts sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float result = (3.f - n * m) / 2.f;
      float out[4] = {result, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTS64: {  // frsqrts dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double result = (3.0 - n * m) / 2.0;
      double out[2] = {result, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTSv2f32: {  // frsqrts vd.2s, vn.2s, vn.2s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      float out[4] = {0.f, 0.f, 0.f, 0.f};
      for (int i = 0; i < 2; i++) {
        out[i] = (3.f - n[i] * m[i]) / 2.f;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTSv4f32: {  // frsqrts vd.4s, vn.4s, vm.4s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      float out[4];
      for (int i = 0; i < 4; i++) {
        out[i] = (3.f - n[i] * m[i]) / 2.f;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FRSQRTSv2f64: {  // frsqrts vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = (3.0 - n[i] * m[i]) / 2.0;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSQRTDr: {  // fsqrt dd, dn
      double out[2] = {::sqrt(operands[0].get<double>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSQRTSr: {  // fsqrt sd, sn
      float out[4] = {::sqrtf(operands[0].get<float>()), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSQRT_ZPmZ_S: {  // fsqrt zd.s, pg/m, zn.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const float* n = operands[1].getAsVector<float>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = ::sqrt(n[i]);
        } else {
          out[i] = n[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSQRTv2f64: {  // fsqrt vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {::sqrtf(n[0]), ::sqrtf(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSQRTv4f32: {  // fsqrt vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {::sqrtf(n[0]), ::sqrtf(n[1]), ::sqrtf(n[2]),
                      ::sqrtf(n[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUBDrr: {  // fsub dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n - m, 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUBSrr: {  // fsub ss, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n - m, 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUB_ZZZ_D: {  // fsub zd.d, zn.d, zm.d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] - m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUB_ZZZ_S: {  // fsub zd.s, zn.s, zm.s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      float out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = n[i] - m[i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUBv2f64: {  // fsub vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {n[0] - m[0], n[1] - m[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_FSUBv4f32: {  // fsub vd.4s, vn.4s, vm.4s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      float out[4] = {n[0] - m[0], n[1] - m[1], n[2] - m[2], n[3] - m[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_INCB_XPiI: {  // incb xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      const uint64_t VL_bits = 512;
      results[0] = n + ((VL_bits / 8) * imm);
      break;
    }
    case Opcode::AArch64_INCD_XPiI: {  // incd xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      const uint64_t VL_bits = 512;
      results[0] = n + ((VL_bits / 64) * imm);
      break;
    }
    case Opcode::AArch64_INCH_XPiI: {  // inch xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      const uint64_t VL_bits = 512;
      results[0] = n + ((VL_bits / 16) * imm);
      break;
    }
    case Opcode::AArch64_INCW_XPiI: {  // incw xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      const uint64_t VL_bits = 512;
      results[0] = n + ((VL_bits / 32) * imm);
      break;
    }
    case Opcode::AArch64_INSvi32lane: {  // ins vd.s[index1], vn.s[index2]
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint32_t* n = operands[1].getAsVector<uint32_t>();

      uint32_t out[4] = {d[0], d[1], d[2], d[3]};
      out[metadata.operands[0].vector_index] =
          n[metadata.operands[1].vector_index];
      results[0] = out;
      break;
    }
    case Opcode::AArch64_INSvi8gpr: {  // ins vd.b[index], wn
      const uint8_t* d = operands[0].getAsVector<uint8_t>();
      const uint8_t n = operands[1].get<uint32_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = d[i];
      }
      out[metadata.operands[0].vector_index] = n;
      results[0] = out;
      break;
    }
    case Opcode::AArch64_INSvi16gpr: {  // ins vd.h[index], wn
      const uint16_t* d = operands[0].getAsVector<uint16_t>();
      const uint16_t n = operands[1].get<uint32_t>();
      uint16_t out[8];
      for (int i = 0; i < 8; i++) {
        out[i] = d[i];
      }
      out[metadata.operands[0].vector_index] = n;
      results[0] = out;
      break;
    }
    case Opcode::AArch64_INSvi32gpr: {  // ins vd.s[index], wn
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint32_t n = operands[1].get<uint32_t>();
      uint32_t out[4] = {d[0], d[1], d[2], d[3]};
      out[metadata.operands[0].vector_index] = n;
      results[0] = out;
      break;
    }
    case Opcode::AArch64_INSvi64gpr: {  // ins vd.d[index], xn
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t n = operands[1].get<uint64_t>();
      uint64_t out[2] = {d[0], d[1]};
      out[metadata.operands[0].vector_index] = n;
      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1i32: {  // ld1 {vt.s}[index], [xn]
      const int index = metadata.operands[0].vector_index;
      const uint32_t* vt = operands[0].getAsVector<uint32_t>();
      uint32_t out[4];
      for (int i = 0; i < 4; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint32_t>() : vt[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1i64: {  // ld1 {vt.d}[index], [xn]
      const int index = metadata.operands[0].vector_index;
      const uint64_t* vt = operands[0].getAsVector<uint64_t>();
      uint64_t out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint64_t>() : vt[i];
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1i64_POST: {  // ld1 {vt.d}[index], [xn], #8
      const int index = metadata.operands[0].vector_index;
      const uint64_t* vt = operands[0].getAsVector<uint64_t>();
      uint64_t out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint64_t>() : vt[i];
      }
      results[0] = out;
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1RD_IMM: {  // ld1rd {zt.d}, pg/z, [xn, #imm]
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};
      uint8_t index = 0;
      // Check if any lanes are active, otherwise set all to 0 and break early
      bool active = false;
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          active = true;
          break;
        }
      }

      if (active) {
        uint64_t data = memoryData[0].get<uint64_t>();
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active =
              p[index / 8] & (uint64_t)std::pow(2, ((index % 8) * 8));
          out[i] = shifted_active ? data : 0;
          index++;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1RW_IMM: {  // ld1rw {zt.s}, pg/z, [xn, #imm]
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint32_t out[64] = {0};
      uint8_t index = 0;
      // Check if any lanes are active, otherwise set all to 0 and break early
      bool active = false;
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          active = true;
          break;
        }
      }

      if (active) {
        uint32_t data = memoryData[0].get<uint32_t>();
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active =
              p[index / 16] & (uint64_t)std::pow(2, ((index % 16) * 4));
          out[i] = shifted_active ? data : 0;
          index++;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1Rv4s: {  // ld1r {vt.4s}, [xn]
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, val, val};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1Rv4s_POST: {  // ld1r {vt.4s}, [xn], #imm
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, val, val};
      results[0] = out;
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1B: {  // ld1b  {zt.b}, pg/z, [xn, xm]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint8_t index = 0;
      uint8_t out[256] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, i);
        if (p[i / 64] & shifted_active) {
          out[i] = memoryData[index].get<uint8_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1D: {  // ld1d  {zt.d}, pg/z, [xn, xm, lsl #3]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint8_t index = 0;
      uint64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1D_IMM_REAL: {  // ld1d  {zt.d}, pg/z, [xn{, #imm,
                                           // mul vl}]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint8_t index = 0;
      uint64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1W: {  // ld1w  {zt.s}, pg/z, [xn, xm, lsl #2]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint8_t index = 0;
      uint32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = memoryData[index].get<uint32_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1W_IMM_REAL: {  // ld1w  {zt.s}, pg/z, [xn{, #imm,
                                           // mul vl}]
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint8_t index = 0;
      uint32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = memoryData[index].get<uint32_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LD1Twov16b: {  // ld1 {vt1.16b, vt2.16b}, [xn]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      break;
    }
    case Opcode::AArch64_LD1Twov16b_POST: {  // ld1 {vt1.16b, vt2.16b}, [xn],
                                             //   #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDADDLW:  // ldaddl ws, wt, [xn]
      [[fallthrough]];
    case Opcode::AArch64_LDADDW: {  // ldadd ws, wt, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      memoryData[0] = RegisterValue(
          memoryData[0].get<uint32_t>() + operands[0].get<uint32_t>(), 4);
      break;
    }
    case Opcode::AArch64_LD2Twov4s_POST: {  // ld2 {vt1.4s, vt2.4s}, [xn], #imm
      const float* region1 = memoryData[0].getAsVector<float>();
      const float* region2 = memoryData[1].getAsVector<float>();
      float t1[4] = {region1[0], region1[2], region2[0], region2[2]};
      float t2[4] = {region1[1], region1[3], region2[1], region2[3]};
      results[0] = t1;
      results[1] = t2;
      uint64_t offset = 32;
      if (metadata.operandCount == 4) {
        offset = operands[3].get<uint64_t>();
      }
      results[2] = operands[2].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_LDARW: {  // ldar wt, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDAXRX: {  // ldaxr xd, [xn]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = memoryData[1].zeroExtend(4, 16);
      break;
    }
    case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      break;
    }
    case Opcode::AArch64_LDPDpost: {  // ldp dt1, dt2, [xn], #imm
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPDpre: {  // ldp dt1, dt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      break;
    }
    case Opcode::AArch64_LDPQpost: {  // ldp qt1, qt2, [xn], #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPQpre: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDPSi: {  // ldp st1, st2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = memoryData[1].zeroExtend(4, 16);
      break;
    }
    case Opcode::AArch64_LDPWi: {  // ldp wt1, wt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = memoryData[1].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      break;
    }
    case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm]!
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRBBpost: {  // ldrb wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRBBroW: {  // ldrb wt,
                                      //  [xn, wm{, extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRBBroX: {  // ldrb wt,
                                      //  [xn, xm{, extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRDpost: {  // ldr dt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRDpre: {  // ldr dt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      break;
    }
    case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      break;
    }
    case Opcode::AArch64_LDRDui: {  // ldr dt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      break;
    }
    case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRQpost: {  // ldr qt, [xn], #imm
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend {#amount}}]
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int8_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSBWui: {  // ldrsb wt, [xn, #imm]
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int8_t>()))
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
      results[0] = static_cast<int64_t>(memoryData[0].get<int8_t>());
      break;
    }
    case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend {#amount}}]
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend {#amount}}]
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHWui: {  // ldrsh wt, [xn, #imm]
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSHXui: {  // ldrsh xt, [xn, #imm]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSWpost: {  // ldrsw xt, [xn], #simm
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDRSpost: {  // ldr st, [xn], #imm
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRSpre: {  // ldr st, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 16);
      break;
    }
    case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 16);
      break;
    }
    case Opcode::AArch64_LDRSui: {  // ldr st, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 16);
      break;
    }
    case Opcode::AArch64_LDRSWl: {  // ldrsw xt, #imm
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRWpre: {  // ldr wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRWroW: {  // ldr wt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRWroX: {  // ldr wt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 8);
      break;
    }
    case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRXroW: {  // ldr xt, [xn, wn{, extend {#amount}}]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend {#amount}}]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDR_PXI: {  // ldr pt, [xn{, #imm, mul vl}]
      const uint64_t PL_bits = 64;
      const uint16_t partition_num = PL_bits / 8;

      uint64_t out[4] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint8_t data = memoryData[i].get<uint8_t>();
        for (int j = 0; j < 8; j++) {
          out[i / 8] |=
              (data & (1 << j)) ? (uint64_t)std::pow(2, (j + (i * 8))) : 0;
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LDR_ZXI: {  // ldr zt, [xn{, #imm, mul vl}]
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint8_t out[256] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = memoryData[i].get<uint8_t>();
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LDTRSBXi: {  // ldtrsb xt, [xn, #imm]
      // TODO: implement
      results[0] = RegisterValue(0, 8);
      break;
    }
    case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDURDi: {  // ldur dt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      break;
    }
    case Opcode::AArch64_LDURHHi: {  // ldurh wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDURSWi: {  // ldursw xt, [xn, #imm]
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDXRX: {  // ldxr xt, [xn]
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LSLVWr: {  // lslv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>() & 0b11111;
      results[0] = static_cast<uint64_t>(x << y);
      break;
    }
    case Opcode::AArch64_LSLVXr: {  // lslv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>() & 0b111111;
      results[0] = x << y;
      break;
    }
    case Opcode::AArch64_LSL_ZZI_S: {  // lsl zd.s, zn.s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t imm = static_cast<uint32_t>(metadata.operands[2].imm);

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = (n[i] << imm);
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_LSRVWr: {  // lsrv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>() & 0b11111;
      results[0] = static_cast<uint64_t>(x >> y);
      break;
    }
    case Opcode::AArch64_LSRVXr: {  // lsrv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>() & 0b111111;
      results[0] = x >> y;
      break;
    }
    case Opcode::AArch64_MADDXrrr: {  // madd xd, xn, xm, xa
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (x * y);
      break;
    }
    case Opcode::AArch64_MADDWrrr: {  // madd wd, wn, wm, wa
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      auto a = operands[2].get<uint32_t>();
      results[0] = static_cast<uint64_t>(a + (x * y));
      break;
    }
    case Opcode::AArch64_MOVID: {  // movi dd, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, 0};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MOVIv16b_ns: {  // movi vd.16b, #imm
      uint8_t bits = static_cast<uint8_t>(metadata.operands[1].imm);
      uint8_t vector[16];
      for (int i = 0; i < 16; i++) {
        vector[i] = bits;
      }
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MOVIv2d_ns: {  // movi vd.2d, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, bits};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MOVIv2i32: {  // movi vd.2s, #imm{, lsl #shift}
      uint32_t bits = shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, 0, 0};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MOVIv4i32: {  // movi vd.4s, #imm{, LSL #shift}
      uint32_t bits = shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, bits, bits};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MOVKWi: {  // movk wd, #imm
      // Clear 16-bit region offset by `shift` and replace with immediate
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t mask = ~(0xFFFF << shift);
      uint32_t value = (operands[0].get<uint32_t>() & mask) |
                       (metadata.operands[1].imm << shift);
      results[0] = RegisterValue(value, 8);
      break;
    }
    case Opcode::AArch64_MOVKXi: {  // movk xd, #imm
      // Clear 16-bit region offset by `shift` and replace with immediate
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t mask = ~(UINT64_C(0xFFFF) << shift);
      uint64_t value = (operands[0].get<uint64_t>() & mask) |
                       (metadata.operands[1].imm << shift);
      results[0] = value;
      break;
    }
    case Opcode::AArch64_MOVNWi: {  // movn wd, #imm{, LSL #shift}
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t value =
          ~(static_cast<uint64_t>(metadata.operands[1].imm) << shift);
      results[0] = static_cast<uint64_t>(value);
      break;
    }
    case Opcode::AArch64_MOVNXi: {  // movn xd, #imm{, LSL #shift}
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t value =
          ~(static_cast<uint64_t>(metadata.operands[1].imm) << shift);
      results[0] = value;
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZZ: {  // movprfx zd, zn
      // TODO: Adopt hint logic of the MOVPRFX instruction
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MOVZWi: {  // movz wd, #imm
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t value = static_cast<uint64_t>(metadata.operands[1].imm) << shift;
      results[0] = RegisterValue(value, 8);
      break;
    }
    case Opcode::AArch64_MOVZXi: {  // movz xd, #imm
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t value = static_cast<uint64_t>(metadata.operands[1].imm) << shift;
      results[0] = value;
      break;
    }
    case Opcode::AArch64_MRS: {  // mrs xt, (systemreg|Sop0_op1_Cn_Cm_op2)
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MSR: {  // mrs (systemreg|Sop0_op1_Cn_Cm_op2), xt
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MSUBWrrr: {  // msub wd, wn, wm, wa
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      auto a = operands[2].get<uint32_t>();
      results[0] = RegisterValue(a - (x * y), 8);
      break;
    }
    case Opcode::AArch64_MSUBXrrr: {  // msub xd, xn, xm, xa
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      auto a = operands[2].get<uint64_t>();
      results[0] = a - (x * y);
      break;
    }
    case Opcode::AArch64_MVNIv2i32: {  // mvni vd.2s, #imm{, lsl #shift}
      uint32_t bits = ~shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, 0, 0};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MVNIv4i16: {  // mvni vd.4h, #imm{, lsl #shift}
      uint16_t bits = ~shiftValue(
          static_cast<uint16_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint16_t vector[8] = {bits, bits, bits, bits, 0, 0, 0, 0};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MVNIv4i32: {  // mvni vd.4s, #imm{, lsl #shift}
      uint32_t bits = ~shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, bits, bits};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_MVNIv8i16: {  // mvni vd.8h, #imm{, lsl #shift}
      uint16_t bits = ~shiftValue(
          static_cast<uint16_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint16_t vector[8] = {bits, bits, bits, bits, bits, bits, bits, bits};
      results[0] = vector;
      break;
    }
    case Opcode::AArch64_HINT: {  // nop|yield|wfe|wfi|etc...
      // TODO: Observe hints
      break;
    }
    case Opcode::AArch64_ORNWrs: {  // orn wd, wn, wm{, shift{ #amount}}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = RegisterValue(x | y, 8);
      break;
    }
    case Opcode::AArch64_ORNXrs: {  // orn xd, xn, xm{, shift{ #amount}}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = x | y;
      break;
    }
    case Opcode::AArch64_ORRWri: {  // orr wd, wn, #imm
      auto value = operands[0].get<uint32_t>();
      auto result = (value | static_cast<uint32_t>(metadata.operands[2].imm));
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ORRWrs: {  // orr wd, wn, wm{, shift{ #amount}}
      uint32_t result = operands[0].get<uint32_t>() |
                        shiftValue(operands[1].get<uint32_t>(),
                                   metadata.operands[2].shift.type,
                                   metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(result);
      break;
    }
    case Opcode::AArch64_ORRXri: {  // orr xd, xn, #imm
      auto value = operands[0].get<uint64_t>();
      auto result = value | metadata.operands[2].imm;
      results[0] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_ORRXrs: {  // orr xd, xn, xm{, shift{ #amount}}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x | y;
      break;
    }
    case Opcode::AArch64_ORR_PPzPP: {  // orr pd.b, pg/z, pn.b, pm.b
      const uint64_t* g = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      // Divide by 512 as we're operating in blocks of 64-bits
      // and each predicate bit represents 8 bits in Z registers or
      // more generally the VL notion.
      const uint16_t partition_num = VL_bits / 512;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        // Or the two source registers in blocks of 64-bits with
        // the governing predicate as a mask.
        out[i] = g[i] & (n[i] | m[i]);
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_ORR_ZZZ: {  // orr zd.d, zn.d, zm.d
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t* m = operands[1].getAsVector<uint64_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        // OR the two source registers
        out[i] = (n[i] | m[i]);
      }

      results[0] = out;

      break;
    }
    case Opcode::AArch64_ORRv16i8: {  // orr Vd.16b, Vn.16b, Vm.16b
      uint64_t out[2] = {operands[0].getAsVector<uint64_t>()[0] |
                             operands[1].getAsVector<uint64_t>()[0],
                         operands[0].getAsVector<uint64_t>()[1] |
                             operands[1].getAsVector<uint64_t>()[1]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      break;
    }
    case Opcode::AArch64_PTEST_PP: {  // ptest pg, pn.b
      const uint64_t VL_bits = 512;
      const uint64_t* g = operands[0].getAsVector<uint64_t>();
      const uint64_t* s = operands[1].getAsVector<uint64_t>();

      uint64_t masked_n[4] = {(g[0] & s[0]), (g[1] & s[1]), (g[2] & s[2]),
                              (g[3] & s[3])};

      uint8_t n = (masked_n[0] & 1);
      uint8_t z = 1;
      // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
      // predicate register we're working in. std::pow(2, (VL_bits / 8) - 1)
      // derives a 1 in the last position of the current predicate. Both
      // dictated by vector length.
      uint8_t c = !(masked_n[(int)((VL_bits - 1) / 512)] &
                    (uint64_t)std::pow(2, 64 - 1));
      for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
        if (masked_n[i]) {
          z = 0;
          break;
        }
      }
      results[0] = nzcv(n, z, c, 0);
      break;
    }
    case Opcode::AArch64_PTRUE_B: {  // ptrue pd.b{, pattern}
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, i);
        out[i / 64] |= shifted_active;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_PTRUE_D: {  // ptrue pd.d{, pattern}
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        out[i / 8] |= shifted_active;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_PTRUE_S: {  // ptrue pd.s{, pattern}
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        out[i / 16] |= shifted_active;
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_PUNPKHI_PP: {  // punpkhi pd.h, pn.b
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint64_t out[4] = {0, 0, 0, 0};
      uint8_t index = 0;

      for (int i = partition_num / 2; i < partition_num; i++) {
        if (n[i / 64] & ((uint64_t)std::pow(2, (i % 64)))) {
          out[index / 32] |= (uint64_t)std::pow(2, (index * 2));
        }
        index++;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_PUNPKLO_PP: {  // punpklo pd.h, pn.b
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint64_t out[4] = {0, 0, 0, 0};

      for (int i = 0; i < partition_num / 2; i++) {
        if (n[i / 64] & ((uint64_t)std::pow(2, (i % 64)))) {
          out[i / 32] |= (uint64_t)std::pow(2, (i * 2));
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_RBITWr:    // rbit wd, wn
    case Opcode::AArch64_RBITXr: {  // rbit xd, xn
      int width = metadata.opcode == Opcode::AArch64_RBITWr ? 32 : 64;

      static uint8_t reversedNibble[16] = {
          0b0000, 0b1000, 0b0100, 0b1100, 0b0010, 0b1010, 0b0110, 0b1110,
          0b0001, 0b1001, 0b0101, 0b1101, 0b0011, 0b1011, 0b0111, 0b1111};

      uint64_t n = operands[0].get<uint64_t>();
      uint64_t result = 0;
      for (int i = 0; i < width; i += 4) {
        result <<= 4;
        result |= reversedNibble[n & 0b1111];
        n >>= 4;
      }

      results[0] = result;
      break;
    }
    case Opcode::AArch64_RDVLI_XI: {  // rdvl xd, #imm
      int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);
      const uint64_t VL_bits = 512;
      results[0] = imm * (VL_bits / 8);
      break;
    }
    case Opcode::AArch64_RET: {  // ret {xr}
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      break;
    }
    case Opcode::AArch64_REVXr: {  // rev xd, xn
      auto bytes = operands[0].getAsVector<uint8_t>();
      uint8_t reversed[8];
      // Copy `bytes` backwards onto `reversed`
      std::copy(bytes, bytes + 8, std::rbegin(reversed));
      results[0] = reversed;
      break;
    }
    case Opcode::AArch64_SBCWr: {  // sbc wd, wn, wm
      auto nzcv = operands[0].get<uint8_t>();
      auto x = operands[1].get<uint32_t>();
      auto y = operands[2].get<uint32_t>();
      uint32_t result;
      std::tie(result, std::ignore) = addWithCarry(x, ~y, (nzcv >> 1) & 1);
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SBCXr: {  // sbc xd, xn, xm
      auto nzcv = operands[0].get<uint8_t>();
      auto x = operands[1].get<uint64_t>();
      auto y = operands[2].get<uint64_t>();
      uint64_t result;
      std::tie(result, std::ignore) = addWithCarry(x, ~y, (nzcv >> 1) & 1);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_SBFMWri: {  // sbfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, 0u, r, s, true), 8);
      break;
    }
    case Opcode::AArch64_SBFMXri: {  // sbfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();
      results[0] = bitfieldManipulate(source, UINT64_C(0), r, s, true);
      break;
    }
    case Opcode::AArch64_SCVTFUWDri: {  // scvtf dd, wn
      double out[2] = {static_cast<double>(operands[0].get<int32_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFUWSri: {  // scvtf sd, wn
      int32_t n = operands[0].get<int32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFUXDri: {  // scvtf dd, xn
      double out[2] = {static_cast<double>(operands[0].get<int64_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFUXSri: {  // scvtf sd, xn
      int64_t n = operands[0].get<int64_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFv1i32: {  // scvtf sd, sn
      int32_t n = operands[0].get<int32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFv1i64: {  // scvtf dd, dn
      double out[2] = {static_cast<double>(operands[0].get<int64_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFv2f64: {  // scvtf vd.2d, vn.2d
      const int64_t* n = operands[0].getAsVector<int64_t>();
      double out[2] = {static_cast<double>(n[0]), static_cast<double>(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SCVTFv4f32: {  // scvtf vd.4s, vn.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      float out[4] = {static_cast<float>(n[0]), static_cast<float>(n[1]),
                      static_cast<float>(n[2]), static_cast<float>(n[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SDIVWr: {  // sdiv wd, wn, wm
      auto x = operands[0].get<int32_t>();
      auto y = operands[1].get<int32_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = RegisterValue(x / y, 8);
      }
      break;
    }
    case Opcode::AArch64_SDIVXr: {  // sdiv xd, xn, xm
      auto x = operands[0].get<int64_t>();
      auto y = operands[1].get<int64_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = x / y;
      }
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_D: {  // sel zd.d, pg, zn.d, zm.d
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          out[i] = n[i];
        } else {
          out[i] = m[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_S: {  // sel zd.s, pg, zn.s, zm.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const uint32_t* n = operands[1].getAsVector<uint32_t>();
      const uint32_t* m = operands[2].getAsVector<uint32_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = n[i];
        } else {
          out[i] = m[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_SHLd: {  // shl dd, dn #imm
      const uint64_t n = operands[0].get<uint64_t>();
      int64_t shift = metadata.operands[2].imm;
      uint64_t out[2] = {static_cast<uint64_t>(n << shift), 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SHLv4i32_shift: {  // shl vd.4s, vn.4s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      int64_t shift = metadata.operands[2].imm;
      uint32_t out[4] = {static_cast<uint32_t>(n[0] << shift),
                         static_cast<uint32_t>(n[1] << shift),
                         static_cast<uint32_t>(n[2] << shift),
                         static_cast<uint32_t>(n[3] << shift)};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SMADDLrrr: {  // smaddl xd, wn, wm, xa
      auto n = static_cast<int64_t>(operands[0].get<int32_t>());
      auto m = static_cast<int64_t>(operands[1].get<int32_t>());
      auto a = operands[2].get<int64_t>();
      results[0] = a + (n * m);
      break;
    }
    case Opcode::AArch64_SMAX_ZPmZ_S: {  // smax zd.s, pg/m, zn.s, zm.s
      const int32_t* d = operands[0].getAsVector<int32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const int32_t* n = operands[2].getAsVector<int32_t>();
      const int32_t* m = operands[3].getAsVector<int32_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = std::max(n[i], m[i]);
        } else {
          out[i] = d[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_SMAXv4i32: {  // smax vd.4s, vn.4s, vm.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      const int32_t* m = operands[1].getAsVector<int32_t>();
      int32_t out[4] = {std::max(n[0], m[0]), std::max(n[1], m[1]),
                        std::max(n[2], m[2]), std::max(n[3], m[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SMIN_ZPmZ_S: {  // smin zd.s, pg/m, zn.s, zm.s
      const int32_t* d = operands[0].getAsVector<int32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const int32_t* n = operands[2].getAsVector<int32_t>();
      const int32_t* m = operands[3].getAsVector<int32_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out[64] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out[i] = std::min(n[i], m[i]);
        } else {
          out[i] = d[i];
        }
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_SMINV_VPZ_S: {  // sminv sd, pg, zn.s
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      const int32_t* n = operands[1].getAsVector<int32_t>();

      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      int32_t out = INT32_MAX;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          out = std::min(out, n[i]);
        }
      }

      results[0] = RegisterValue(out, 16);
      break;
    }
    case Opcode::AArch64_SMINVv4i32v: {  // sminv sd, vn.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      int32_t out = std::min(std::min(n[0], n[1]), std::min(n[2], n[3]));
      results[0] = RegisterValue(out, 16);
      break;
    }
    case Opcode::AArch64_SMINv4i32: {  // smin vd.4s, vn.4s, vm.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      const int32_t* m = operands[1].getAsVector<int32_t>();
      int32_t out[4] = {std::min(n[0], m[0]), std::min(n[1], m[1]),
                        std::min(n[2], m[2]), std::min(n[3], m[3])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SMULHrr: {  // smulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      // TODO: signed
      results[0] = mulhi(x, y);
      break;
    }
    case Opcode::AArch64_SSHLLv2i32_shift: {  // sshll vd.2d, vn.2s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {
          static_cast<int64_t>(static_cast<int32_t>(n[0] << shift)),
          static_cast<int64_t>(static_cast<int32_t>(n[1] << shift))};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SSHLLv4i32_shift: {  // sshll2 vd.2d, vn.4s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {
          static_cast<int64_t>(static_cast<int32_t>(n[2] << shift)),
          static_cast<int64_t>(static_cast<int32_t>(n[3] << shift))};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SSHRv4i32_shift: {  // sshr vd.4s, vn.4s, #imm
      const int32_t* n = operands[1].getAsVector<int32_t>();
      uint64_t shift = metadata.operands[2].imm;
      int32_t out[4] = {static_cast<int32_t>(std::trunc(n[0] >> shift)),
                        static_cast<int32_t>(std::trunc(n[1] >> shift)),
                        static_cast<int32_t>(std::trunc(n[2] >> shift)),
                        static_cast<int32_t>(std::trunc(n[3] >> shift))};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ST1B: {  // st1b {zt.b}, pg, [xn, xm]
      const uint8_t* d = operands[0].getAsVector<uint8_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, i);
        if (p[i / 64] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }

      break;
    }
    case Opcode::AArch64_ST1D: {  // st1d {zt.d}, pg, [xn, xm, lsl #3]
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }

      break;
    }
    case Opcode::AArch64_ST1D_IMM: {  // st1d {zt.d}, pg, [xn{, #imm, mul vl}]
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 8));
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }

      break;
    }
    case Opcode::AArch64_ST1W: {  // st1w {zt.s}, pg, [xn, xm, lsl #2]
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }

      break;
    }
    case Opcode::AArch64_ST1W_IMM: {  // st1w {zt.s}, pg, [xn{, #imm, mul vl}]
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = std::pow(2, (i * 4));
        if (p[i / 16] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }

      break;
    }
    case Opcode::AArch64_ST1Twov16b: {  // st1v {vt.16b, vt2.16b}, [xn]
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      const uint8_t* t2 = operands[1].getAsVector<uint8_t>();
      for (int i = 0; i < 16; i++) {
        memoryData[i] = t[i];
      }
      for (int i = 0; i < 16; i++) {
        memoryData[i + 16] = t2[i];
      }
      break;
    }
    case Opcode::AArch64_ST1i8: {  // st1 {vt.b}[index], [xn]
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i16: {  // st1 {vt.h}[index], [xn]
      const uint16_t* t = operands[0].getAsVector<uint16_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i32: {  // st1 {vt.s}[index], [xn]
      const uint32_t* t = operands[0].getAsVector<uint32_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i64: {  // st1 {vt.d}[index], [xn]
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i8_POST: {  // st1 {vt.b}[index], [xn], xm
                                        // st1 {vt.b}[index], [xn], #1
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 1;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = RegisterValue(operands[1].get<uint64_t>() + offset, 8);
      break;
    }
    case Opcode::AArch64_ST1i16_POST: {  // st1 {vt.h}[index], [xn], xm
                                         // st1 {vt.h}[index], [xn], #2
      const uint16_t* t = operands[0].getAsVector<uint16_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 2;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST1i32_POST: {  // st1 {vt.s}[index], [xn], xm
                                         // st1 {vt.s}[index], [xn], #4
      const uint32_t* t = operands[0].getAsVector<uint32_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 4;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST1i64_POST: {  // st1 {vt.d}[index], [xn], xm
                                         // st1 {vt.d}[index], [xn], #8
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 8;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST2Twov4s_POST: {  // st2 {vt1.4s, vt2.4s}, [xn], #imm
      const float* t1 = operands[0].getAsVector<float>();
      const float* t2 = operands[1].getAsVector<float>();
      for (int i = 0; i < 4; i++) {
        memoryData[2 * i] = t1[i];
        memoryData[2 * i + 1] = t2[i];
      }
      uint64_t offset = 32;
      if (metadata.operandCount == 4) {
        offset = operands[3].get<uint64_t>();
      }
      results[0] = operands[2].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_STLRB:  // stlrb wt, [xn]
      [[fallthrough]];
    case Opcode::AArch64_STLRW: {  // stlr wt, [xn]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STLXRW:  // stlxr ws, wt, [xn]
      [[fallthrough]];
    case Opcode::AArch64_STLXRX: {  // stlxr ws, xt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_STPDi: {  // stp dt1, dt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPDpost: {  // stp dt1, dt2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPDpre: {  // stp dt1, dt2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPSi: {  // stp st1, st2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPSpost: {  // stp st1, st2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPSpre: {  // stp st1, st2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPXpost: {  // stp xt1, xt2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPQpre: {  // stp qt1, qt2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPWi: {  // stp wt1, wt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STRBBpost: {  // strb wd, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRBBpre: {  // strb wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRBBroW: {  // strb wd,
                                      //  [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRBBroX: {  // strb wd,
                                      //  [xn, xm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRDpre: {  // str dd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRHHroW: {  // strh wd,
                                      //  [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHroX: {  // strh wd,
                                      //  [xn, xm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRQpost: {  // str qt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRQpre: {  // str qt, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSpost: {  // str st, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRSpre: {  // str sd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSui: {  // str st, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRWpre: {  // str wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRWroW: {  // str wd, [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRXpre: {  // str xd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRXroW: {  // str xd, [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STR_PXI: {  // str pt, [xn{, #imm, mul vl}]
      const uint64_t PL_bits = 64;
      const uint16_t partition_num = PL_bits / 8;
      const uint8_t* p = operands[0].getAsVector<uint8_t>();

      for (int i = 0; i < partition_num; i++) {
        memoryData[i] = p[i];
      }

      break;
    }
    case Opcode::AArch64_STR_ZXI: {  // str zt, [xn{, #imm, mul vl}]
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      const uint8_t* z = operands[0].getAsVector<uint8_t>();

      for (int i = 0; i < partition_num; i++) {
        memoryData[i] = z[i];
      }

      break;
    }
    case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURDi: {  // stur dt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURHHi: {  // sturh wt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURQi: {  // stur qt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURSi: {  // stur st, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURXi: {  // stur xt, [xn, #imm]
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_STXRX: {  // stxr ws, xt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_SUBv4i32: {  // sub vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] - m[0], n[1] - m[1], n[2] - m[2], n[3] - m[3]};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_SUBSWri: {  // subs wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = RegisterValue(result, 8);
      }
      break;
    }
    case Opcode::AArch64_SUBSWrs: {  // subs wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = RegisterValue(result, 8);
      }
      break;
    }
    case Opcode::AArch64_SUBSWrx: {  // subs wd, wn, wm{, extend #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(
          ~extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                       metadata.operands[2].shift.value));
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = RegisterValue(result, 8);
      }
      break;
    }
    case Opcode::AArch64_SUBSXri: {  // subs xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = RegisterValue(result);
      }
      break;
    }
    case Opcode::AArch64_SUBSXrs: {  // subs xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = RegisterValue(result);
      }
      break;
    }
    case Opcode::AArch64_SUBSXrx: {  // subs xd, xn, wm{, extend #amount}
      auto x = operands[0].get<uint64_t>();
      auto y =
          ~extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                       metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = result;
      }
      break;
    }
    case Opcode::AArch64_SUBSXrx64: {  // subs xd, xn, xm{, extend #amount}
      auto x = operands[0].get<uint64_t>();
      auto y =
          ~extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                       metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      if (destinationRegisterCount > 1) {
        results[1] = result;
      }
      break;
    }
    case Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y, 8);
      break;
    }
    case Opcode::AArch64_SUBWrs: {  // sub wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y, 8);
      break;
    }
    case Opcode::AArch64_SUBXri: {  // sub xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y);
      break;
    }
    case Opcode::AArch64_SUBXrs: {  // sub xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x - y;
      break;
    }
    case Opcode::AArch64_SUBXrx: {  // sub xd, xn, wm{, extend #amount}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x - y;
      break;
    }
    case Opcode::AArch64_SUBXrx64: {  // sub xd, xn, xm{, extend #amount}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x - y;
      break;
    }
    case Opcode::AArch64_SVC: {  // svc #imm
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      break;
    }
    case Opcode::AArch64_SYSxt: {  // sys #<op1>, cn, cm, #<op2>{, xt}
      if (metadata.id == ARM64_INS_DC) {
        uint64_t address = operands[0].get<uint64_t>();
        uint8_t dzp = operands[1].get<uint64_t>() & 8;
        uint8_t N = std::pow(2, operands[1].get<uint64_t>() & 7);
        if (metadata.operands[0].sys == ARM64_DC_ZVA) {
          if (dzp) {
            // TODO
          }
        }
      }
      break;
    }
    case Opcode::AArch64_TBNZW: {  // tbnz wn, #imm, label
      if (operands[0].get<uint32_t>() & (1 << metadata.operands[1].imm)) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_TBNZX: {  // tbnz xn, #imm, label
      if (operands[0].get<uint64_t>() & (1ull << metadata.operands[1].imm)) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_TBZW: {  // tbz wn, #imm, label
      if (operands[0].get<uint32_t>() & (1 << metadata.operands[1].imm)) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      }
      break;
    }
    case Opcode::AArch64_TBZX: {  // tbz xn, #imm, label
      if (operands[0].get<uint64_t>() & (1ull << metadata.operands[1].imm)) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      }
      break;
    }
    case Opcode::AArch64_UBFMWri: {  // ubfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, 0u, r, s), 8);
      break;
    }
    case Opcode::AArch64_UBFMXri: {  // ubfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();
      results[0] = bitfieldManipulate(source, UINT64_C(0), r, s);
      break;
    }
    case Opcode::AArch64_UQDECD_XPiI: {  // uqdecd xd{, pattern{, MUL #imm}}
      const uint64_t d = operands[0].get<uint64_t>();
      const uint8_t imm = metadata.operands[1].imm;
      const uint64_t VL_bits = 512;

      int64_t out = d - (imm * (VL_bits / 64));
      // Saturate output
      if (out > (std::pow(2, 64) - 1)) {
        out = std::pow(2, 64) - 1;
      } else if (out < 0) {
        out = 0;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_UQDECH_XPiI: {  // uqdech xd{, pattern{, MUL #imm}}
      const uint64_t d = operands[0].get<uint64_t>();
      const uint8_t imm = metadata.operands[1].imm;
      const uint64_t VL_bits = 512;

      int64_t out = d - (imm * (VL_bits / 16));
      // Saturate output
      if (out > (std::pow(2, 64) - 1)) {
        out = std::pow(2, 64) - 1;
      } else if (out < 0) {
        out = 0;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_UQDECW_XPiI: {  // uqdecw xd{, pattern{, MUL #imm}}
      const uint64_t d = operands[0].get<uint64_t>();
      const uint8_t imm = metadata.operands[1].imm;
      const uint64_t VL_bits = 512;

      int64_t out = d - (imm * (VL_bits / 32));
      // Saturate output
      if (out > (std::pow(2, 64) - 1)) {
        out = std::pow(2, 64) - 1;
      } else if (out < 0) {
        out = 0;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFUWDri: {  // ucvtf dd, wn
      double out[2] = {static_cast<double>(operands[0].get<uint32_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFUWSri: {  // ucvtf sd, wn
      uint32_t n = operands[0].get<uint32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFUXDri: {  // ucvtf dd, xn
      double out[2] = {static_cast<double>(operands[0].get<uint64_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFUXSri: {  // ucvtf sd, xn
      uint64_t n = operands[0].get<uint64_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFv1i32: {  // ucvtf sd, sn
      uint32_t n = operands[0].get<uint32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UCVTFv1i64: {  // ucvtf dd, dn
      double out[2] = {static_cast<double>(operands[0].get<uint64_t>()), 0.0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UDIVWr: {  // udiv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = RegisterValue(x / y, 8);
      }
      break;
    }
    case Opcode::AArch64_UDIVXr: {  // udiv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = x / y;
      }
      break;
    }
    case Opcode::AArch64_UMADDLrrr: {  // umaddl xd, wn, wm, xa
      auto n = static_cast<uint64_t>(operands[0].get<uint32_t>());
      auto m = static_cast<uint64_t>(operands[1].get<uint32_t>());
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (n * m);
      break;
    }
    case Opcode::AArch64_UMOVvi32: {  // umov wd, vn.s[index]
      const uint32_t* vec = operands[0].getAsVector<uint32_t>();
      results[0] = RegisterValue(vec[metadata.operands[1].vector_index], 8);
      break;
    }
    case Opcode::AArch64_UMOVvi64: {  // umov xd, vn.d[index]
      const uint64_t* vec = operands[0].getAsVector<uint64_t>();
      results[0] = vec[metadata.operands[1].vector_index];
      break;
    }
    case Opcode::AArch64_UMOVvi8: {  // umov wd, vn.b[index]
      const uint8_t* vec = operands[0].getAsVector<uint8_t>();
      results[0] = RegisterValue(vec[metadata.operands[1].vector_index], 8);
      break;
    }
    case Opcode::AArch64_UMSUBLrrr: {  // umsubl xd, wn, wm, xa
      uint64_t n = static_cast<uint64_t>(operands[0].get<uint32_t>());
      uint64_t m = static_cast<uint64_t>(operands[1].get<uint32_t>());
      uint64_t a = operands[2].get<uint64_t>();
      results[0] = a - (n * m);
      break;
    }
    case Opcode::AArch64_UMULHrr: {  // umulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = mulhi(x, y);
      break;
    }
    case Opcode::AArch64_USHLLv4i16_shift: {  // ushll vd.4s, vn.4h, #imm
      const uint16_t* n = operands[0].getAsVector<uint16_t>();
      int64_t shift = metadata.operands[2].imm;
      uint16_t out[8] = {static_cast<uint16_t>(n[0] << shift), 0,
                         static_cast<uint16_t>(n[1] << shift), 0,
                         static_cast<uint16_t>(n[2] << shift), 0,
                         static_cast<uint16_t>(n[3] << shift), 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_UZP1_ZZZ_S: {  // uzp1 zd.s, zn.s, zm.s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint32_t out[64] = {0};

      for (int i = 0; i < partition_num / 2; i++) {
        out[i] = n[2 * i];
      }
      for (int i = 0; i < partition_num / 2; i++) {
        out[partition_num / 2 + i] = m[2 * i];
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_B: {  // whilelo pd.b, xn, xm
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 8;
      uint64_t out[4] = {0, 0, 0, 0};
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        // Determine whether lane should be active and shift to align with
        // element in predicate register.
        uint64_t shifted_active = (n + i) < m ? std::pow(2, i) : 0;
        out[index / 64] = out[index / 64] | shifted_active;
        index++;
      }

      uint8_t N = (out[0] & 1);
      uint8_t Z = 1;
      // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
      // predicate register we're working in. std::pow(2, (VL_bits / 8) - 1)
      // derives a 1 in the last position of the current predicate. Both
      // dictated by vector length.
      uint8_t C =
          !(out[(int)((VL_bits - 1) / 512)] & (uint64_t)std::pow(2, 64 - 1));
      for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
        if (out[i]) {
          Z = 0;
          break;
        }
      }
      results[0] = nzcv(N, Z, C, 0);
      results[1] = out;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_D: {  // whilelo pd.d, xn, xm
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[4] = {0, 0, 0, 0};
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        // Determine whether lane should be active and shift to align with
        // element in predicate register.
        uint64_t shifted_active = (n + i) < m ? std::pow(2, (i * 8)) : 0;
        out[index / 8] = out[index / 8] | shifted_active;
        index++;
      }

      uint8_t N = (out[0] & 1);
      uint8_t Z = 1;
      // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
      // predicate register we're working in. std::pow(2, (VL_bits / 8) - 1)
      // derives a 1 in the last position of the current predicate. Both
      // dictated by vector length.
      uint8_t C =
          !(out[(int)((VL_bits - 1) / 512)] & (uint64_t)std::pow(2, 64 - 8));
      for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
        if (out[i]) {
          Z = 0;
          break;
        }
      }
      results[0] = nzcv(N, Z, C, 0);
      results[1] = out;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_S: {  // whilelo pd.s, xn, xm
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 32;
      uint64_t out[4] = {0, 0, 0, 0};
      uint8_t index = 0;

      for (int i = 0; i < partition_num; i++) {
        // Determine whether lane should be active and shift to align with
        // element in predicate register.
        uint64_t shifted_active = (n + i) < m ? std::pow(2, (i * 4)) : 0;
        out[index / 16] = out[index / 16] | shifted_active;
        index++;
      }

      uint8_t N = (out[0] & 1);
      uint8_t Z = 1;
      // (int)(VL_bits - 1)/512 derives which block of 64-bits within the
      // predicate register we're working in. std::pow(2, (VL_bits / 8) - 1)
      // derives a 1 in the last position of the current predicate. Both
      // dictated by vector length.
      uint8_t C =
          !(out[(int)((VL_bits - 1) / 512)] & (uint64_t)std::pow(2, 64 - 4));
      for (int i = 0; i < (int)((VL_bits - 1) / 512) + 1; i++) {
        if (out[i]) {
          Z = 0;
          break;
        }
      }
      results[0] = nzcv(N, Z, C, 0);
      results[1] = out;
      break;
    }
    case Opcode::AArch64_XTNv2i32: {  // xtn vd.2s, vn.2d
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0]),
                         static_cast<uint32_t>(n[1]), 0, 0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_XTNv4i16: {  // xtn vd.4h, vn.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint16_t out[8] = {static_cast<uint16_t>(n[0]),
                         static_cast<uint16_t>(n[1]),
                         static_cast<uint16_t>(n[2]),
                         static_cast<uint16_t>(n[3]),
                         0,
                         0,
                         0,
                         0};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_XTNv4i32: {  // xtn2 vd.4s, vn.2d
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      uint32_t out[4] = {d[0], d[1], static_cast<uint32_t>(n[0]),
                         static_cast<uint32_t>(n[1])};
      results[0] = out;
      break;
    }
    case Opcode::AArch64_ZIP1_ZZZ_D: {  // zip1 zd.d, zn.d, zm.d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      bool interleave = false;
      int index = 0;
      for (int i = 0; i < partition_num; i++) {
        if (interleave) {
          out[i] = m[index];
          index++;
        } else {
          out[i] = n[index];
        }
        interleave = !interleave;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_ZIP2_ZZZ_D: {  // zip2 zd.d, zn.d, zm.d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      const uint64_t VL_bits = 512;
      const uint16_t partition_num = VL_bits / 64;
      double out[32] = {0};

      bool interleave = false;
      int index = partition_num / 2;
      for (int i = 0; i < partition_num; i++) {
        if (interleave) {
          out[i] = m[index];
          index++;
        } else {
          out[i] = n[index];
        }
        interleave = !interleave;
      }

      results[0] = out;
      break;
    }
    case Opcode::AArch64_XPACLRI: {  // xpaclri
      // SimEng doesn't support PAC, so do nothing
      break;
    }
    default:
      return executionNYI();
  }
  // Zero-out upper bits of vector registers because Z configuration
  // extend to 256 bytes whilst V configurations only extend to 16 bytes.
  // Thus upper 240 bytes must be ignored by being set to 0.
  for (int i = 0; i < destinationRegisterCount; i++) {
    if ((destinationRegisters[i].type == RegisterType::VECTOR) && !isSVEData_) {
      results[i] = results[i].zeroExtend(16, 256);
    }
  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng