#include "simeng/arch/aarch64/Instruction.hh"

#include "InstructionMetadata.hh"

#include <cmath>
#include <limits>
#include <tuple>

#include<iostream>

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

  std::cout << metadata.mnemonic;
  if(isShift_){
    std::cout << " SHIFT";
  }
  if(isASIMD_){
    std::cout << " ASIMD";
  }
  std::cout << std::endl;

  executed_ = true;
  switch (metadata.opcode) {
    case Opcode::AArch64_ADDv1i64: {  // add dd, dn, dm
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out[2] = {static_cast<uint64_t>(n + m), 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_ADDv4i32: {  // add vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] + m[0]),
                         static_cast<uint32_t>(n[1] + m[1]),
                         static_cast<uint32_t>(n[2] + m[2]), 
                         static_cast<uint32_t>(n[3] + m[3])};
      results[0] = out;
      return;
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
      return;
    }
    case Opcode::AArch64_ADDPv2i64: {  // addp vd.2d, vn.2d, vm.2d
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t* m = operands[1].getAsVector<uint64_t>();
      uint64_t out[2] = {n[0] + n[1], m[0] + m[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_ADDPv4i32: {  // addp vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] + n[1], n[2] + n[3], m[0] + m[1], m[2] + m[3]};
      results[0] = out;
      return;
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
      return;
    }
    case Opcode::AArch64_ADDSWri: {  // adds wd, wn, #imm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_ADDSWrs: {  // adds wd, wn, wm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_ADDSWrx: {  // adds wd, wn, wm{, extend {#amount}}
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value));
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_ADDSXri: {  // adds xd, xn, #imm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      return;
    }
    case Opcode::AArch64_ADDSXrs: {  // adds xd, xn, xm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      return;
    }
    case Opcode::AArch64_ADDSXrx: {  // adds xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      return;
    }
    case Opcode::AArch64_ADDSXrx64: {  // adds xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      auto [result, nzcv] = addWithCarry(x, y, 0);
      results[0] = nzcv;
      results[1] = result;
      return;
    }
    case Opcode::AArch64_ADDWri: {  // add wd, wn, #imm{, shift}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x + y, 8);
      return;
    }
    case Opcode::AArch64_ADDWrs: {  // add wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(x + y);
      return;
    }
    case Opcode::AArch64_ADDXri: {  // add xd, xn, #imm{, shift}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x + y);
      return;
    }
    case Opcode::AArch64_ADDXrs: {  // add xd, xn, xm, {shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x + y;
      return;
    }
    case Opcode::AArch64_ADDXrx: {  // add xd, xn, wm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint32_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x + y;
      return;
    }
    case Opcode::AArch64_ADDXrx64: {  // add xd, xn, xm{, extend {#amount}}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x + y;
      return;
    }
    case Opcode::AArch64_ADR: {  // adr xd, #imm
      results[0] = instructionAddress_ + metadata.operands[1].imm;
      return;
    }
    case Opcode::AArch64_ADRP: {  // adrp xd, #imm
      // Clear lowest 12 bits of address and add immediate (already shifted by
      // decoder)
      results[0] = (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
      return;
    }
    case Opcode::AArch64_ANDSWri: {  // ands wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      uint32_t result = x & y;
      results[0] = nzcv(result >> 31, result == 0, false, false);
      results[1] = RegisterValue(result, 8);
      return;
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
      return;
    }
    case Opcode::AArch64_ANDSXri: {  // ands xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      uint64_t result = x & y;
      results[0] = nzcv(result >> 63, result == 0, false, false);
      results[1] = result;
      return;
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
      return;
    }
    case Opcode::AArch64_ANDWri: {  // and wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      uint32_t result = x & y;
      results[0] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_ANDWrs: {  // and wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(x & y);
      return;
    }
    case Opcode::AArch64_ANDXri: {  // and xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      results[0] = x & y;
      return;
    }
    case Opcode::AArch64_ANDXrs: {  // and xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x & y;
      return;
    }
    case Opcode::AArch64_ANDv16i8: {  // and vd.16b, vn.16b, vm.16b
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      const uint64_t* m = operands[1].getAsVector<uint64_t>();
      uint64_t out[2] = {n[0] & m[0], n[1] & m[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_ANDv8i8: {  // and vd.8b, vn.8b, vm.8b
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] & m[0], n[1] & m[1], 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_ASRVWr: {  // asrv wd, wn, wm
      auto n = operands[0].get<int32_t>();
      auto m = operands[1].get<uint32_t>();
      results[0] = RegisterValue(n >> (m % 32), 8);
      return;
    }
    case Opcode::AArch64_ASRVXr: {  // asrv xd, xn, xm
      auto n = operands[0].get<int64_t>();
      auto m = operands[1].get<uint64_t>();
      results[0] = n >> (m % 64);
      return;
    }
    case Opcode::AArch64_B: {  // b label
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      return;
    }
    case Opcode::AArch64_BFMWri: {  // bfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t dest = operands[0].get<uint32_t>();
      uint32_t source = operands[1].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, dest, r, s), 8);
      return;
    }
    case Opcode::AArch64_BFMXri: {  // bfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t dest = operands[0].get<uint64_t>();
      uint64_t source = operands[1].get<uint64_t>();
      results[0] = bitfieldManipulate(source, dest, r, s);
      return;
    }
    case Opcode::AArch64_BICWrs: {  // bic wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = RegisterValue(x & y, 8);
      return;
    }
    case Opcode::AArch64_BICXrs: {  // bic xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = x & y;
      return;
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
      return;
    }
    case Opcode::AArch64_Bcc: {  // b.cond label
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
    }
    case Opcode::AArch64_BIFv16i8: {  // bif vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      uint64_t out[2] = {(d[0] & m[0]) | (n[0] & ~m[0]),
                         (d[1] & m[1]) | (n[1] & ~m[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_BITv16i8: {  // bit vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();  
      uint64_t out[2] = {(d[0] & ~m[0]) | (n[0] & m[0]),
                         (d[1] & ~m[1]) | (n[1] & m[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_BL: {  // bl #imm
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      return;
    }
    case Opcode::AArch64_BR: {  // br xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      return;
    }
    case Opcode::AArch64_BLR: {  // blr xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      return;
    }
    case Opcode::AArch64_BSLv16i8: {  // bsl vd.16b, vn.16b, vm.16b
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      const uint64_t* m = operands[2].getAsVector<uint64_t>();
      uint64_t out[2] = {(d[0] & n[0]) | ((~d[0]) & m[0]),
                         (d[1] & n[1]) | ((~d[1]) & m[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_CBNZW: {  // cbnz wn, #imm
      if (operands[0].get<uint32_t>() == 0) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      }
      return;
    }
    case Opcode::AArch64_CBNZX: {  // cbnz xn, #imm
      if (operands[0].get<uint64_t>() == 0) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      }
      return;
    }
    case Opcode::AArch64_CBZW: {  // cbz wn, #imm
      if (operands[0].get<uint32_t>() == 0) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
    }
    case Opcode::AArch64_CBZX: {  // cbz xn, #imm
      if (operands[0].get<uint64_t>() == 0) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[1].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
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
      return;
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
      return;
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
      return;
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
      return;
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
      return;
    }
    case Opcode::AArch64_CMEQv16i8: {  // cmeq vd.16b, vn.16b, vm.16b
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint8_t* m = operands[1].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = (n[i] == m[i]) ? 0xFF : 0;
      }
      results[0] = out;
      return;
    }
    case Opcode::AArch64_CMEQv16i8rz: {  // cmeq vd.16b, vn.16b, #0
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      uint8_t out[16];
      for (int i = 0; i < 16; i++) {
        out[i] = (n[i] == 0) ? 0xFF : 0;
      }
      results[0] = out;
      return;
    }
    case Opcode::AArch64_CPYi32: {  // dup vd, vn.s[index]
      const uint32_t* vec = operands[0].getAsVector<uint32_t>();
      uint32_t out[4] = {vec[metadata.operands[1].vector_index], 0, 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_CPYi64: {  // dup vd, vn.d[index]
      const uint64_t* vec = operands[0].getAsVector<uint64_t>();
      uint64_t out[2] = {vec[metadata.operands[1].vector_index], 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_CSELWr: {  // csel wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = static_cast<uint64_t>(operands[1].get<uint32_t>());
      } else {
        results[0] = static_cast<uint64_t>(operands[2].get<uint32_t>());
      }
      return;
    }
    case Opcode::AArch64_CSELXr: {  // csel xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = operands[2].get<uint64_t>();
      }
      return;
    }
    case Opcode::AArch64_CSNEGWr: {  // csneg wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = static_cast<int64_t>(operands[1].get<int32_t>());
      } else {
        results[0] = static_cast<int64_t>(-operands[2].get<int32_t>());
      }
      return;
    }
    case Opcode::AArch64_CSNEGXr: {  // csneg xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<int64_t>();
      } else {
        results[0] = -operands[2].get<int64_t>();
      }
      return;
    }
    case Opcode::AArch64_CSINCWr: {  // csinc wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = RegisterValue(operands[1].get<uint32_t>(), 8);
      } else {
        results[0] = RegisterValue(operands[2].get<uint32_t>() + 1, 8);
      }
      return;
    }
    case Opcode::AArch64_CSINCXr: {  // csinc xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = operands[2].get<uint64_t>() + 1;
      }
      return;
    }
    case Opcode::AArch64_CSINVWr: {  // csinv wd, wn, wm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = RegisterValue(operands[1].get<uint32_t>(), 8);
      } else {
        results[0] = RegisterValue(~operands[2].get<uint32_t>(), 8);
      }
      return;
    }
    case Opcode::AArch64_CSINVXr: {  // csinv xd, xn, xm, cc
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        results[0] = operands[1].get<uint64_t>();
      } else {
        results[0] = ~operands[2].get<uint64_t>();
      }
      return;
    }
    case Opcode::AArch64_DUPv16i8gpr: {  // dup vd.16b, wn
      uint8_t out[16];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint8_t>());
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv2i32gpr: {  // dup vd.2s, wn
      uint32_t element = operands[0].get<uint32_t>();
      uint32_t out[4] = {element, element, 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv2i32lane: {  // dup vd.2s, vn.s[index]
      int index = metadata.operands[1].vector_index;
      uint32_t element = operands[0].getAsVector<uint32_t>()[index];
      uint32_t out[4] = {element, element, 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv2i64gpr: {  // dup vd.2d, xn
      uint64_t out[2];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint64_t>());
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv2i64lane: {  // dup vd.2d, vn.d[index]
      int index = metadata.operands[1].vector_index;
      uint64_t element = operands[0].getAsVector<uint64_t>()[index];
      uint64_t out[2];
      std::fill(std::begin(out), std::end(out), element);
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv4i16gpr: {  // dup vd.4h, wn
      uint16_t element = operands[0].get<uint16_t>();
      uint16_t out[8] = {element, element, element, element, 0, 0, 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv4i32gpr: {  // dup vd.4s, wn
      uint32_t out[4];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint32_t>());
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DUPv4i32lane: {  // dup vd.4s, vn.s[index]
      int index = metadata.operands[1].vector_index;
      uint32_t element = operands[0].getAsVector<uint32_t>()[index];
      uint32_t out[4];
      std::fill(std::begin(out), std::end(out), element);
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DMB: {  // dmb option|#imm
      // TODO: Respect memory barriers
      return;
    }
    case Opcode::AArch64_EORWri: {  // eor wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      results[0] = RegisterValue(x ^ y, 8);
      return;
    }
    case Opcode::AArch64_EORWrs: {  // eor wd, wn, wm{, shift #imm}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x ^ y, 8);
      return;
    }
    case Opcode::AArch64_EORXri: {  // eor xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = static_cast<uint64_t>(metadata.operands[2].imm);
      results[0] = x ^ y;
      return;
    }
    case Opcode::AArch64_EORXrs: {  // eor xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x ^ y;
      return;
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
      return;
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
      return;
    }
    case Opcode::AArch64_FABSDr: {  // fabs dd, dn
      double n = operands[0].get<double>();
      double out[2] = {std::fabs(n), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FABSSr: {  // fabs sd, sn
      float n = operands[0].get<float>();
      float out[4] = {std::fabs(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FABSv2f64: {  // fabs vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fabs(n[0]), std::fabs(n[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FABSv4f32: {  // fabs vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {std::fabs(n[0]), std::fabs(n[1]), std::fabs(n[2]),
                      std::fabs(n[3])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FADDDrr: {  // fadd dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n + m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FADDSrr: {  // fadd sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n + m, 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] + b[0], a[1] + b[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FADDv4f32: {  // fadd vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      float out[4] = {a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FADDPv2i64p: {  // faddp dd, vn.2d
      const double* a = operands[0].getAsVector<double>();
      double out[2] = {a[0] + a[1], 0.0};
      results[0] = out;
      return;
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
      return;
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
      return;
    }
    case Opcode::AArch64_FCMGEv2i64rz: {  // fcmge vd.2d, vn.2d, 0.0
      const double* n = operands[0].getAsVector<double>();
      uint64_t out[2] = {static_cast<uint64_t>(n[0] >= 0.0 ? -1 : 0),
                         static_cast<uint64_t>(n[1] >= 0.0 ? -1 : 0)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCMGEv4i32rz: {  // fcmge vd.4s, vn.4s, 0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[1] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[2] >= 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[3] >= 0.0 ? -1 : 0)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCMGTv4f32: {  // fcmgt vd.4s, vn.4s, vm.4s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] > m[0] ? -1 : 0),
                         static_cast<uint32_t>(n[1] > m[1] ? -1 : 0),
                         static_cast<uint32_t>(n[2] > m[2] ? -1 : 0),
                         static_cast<uint32_t>(n[3] > m[3] ? -1 : 0)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCMLTv4i32rz: {  // fcmlt vd.4s, vn.4s, #0.0
      const float* n = operands[0].getAsVector<float>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[1] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[2] < 0.0 ? -1 : 0),
                         static_cast<uint32_t>(n[3] < 0.0 ? -1 : 0)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCMPDri:  // fcmp dn, #imm
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
      return;
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
      return;
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
      return;
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
      return;
    }
    case Opcode::AArch64_FCSELDrrr: {  // fcsel dd, dn, dm, cond
      double n = operands[1].get<double>();
      double m = operands[2].get<double>();
      double out[2] = {
          conditionHolds(metadata.cc, operands[0].get<uint8_t>()) ? n : m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCSELSrrr: {  // fcsel sd, sn, sm, cond
      float n = operands[1].get<float>();
      float m = operands[2].get<float>();
      float out[4] = {
          conditionHolds(metadata.cc, operands[0].get<uint8_t>()) ? n : m, 0.f,
          0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCVTDSr: {  // fcvt dd, sn
      // TODO: Handle NaNs, denorms, and saturation?
      double out[2] = {static_cast<double>(operands[0].get<float>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCVTSDr: {  // fcvt sd, dn
      // TODO: Handle NaNs, denorms, and saturation?
      float out[4] = {static_cast<float>(operands[0].get<double>()), 0.f, 0.f,
                      0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCVTZSUWDr: {  // fcvtzs wd, dn
      double n = operands[0].get<double>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      return;
    }
    case Opcode::AArch64_FCVTZSUWSr: {  // fcvtzs wd, sn
      float n = operands[0].get<float>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      return;
    }
    case Opcode::AArch64_FCVTZSv2f64: {  // fcvtzs vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      // TODO: Handle NaNs, denorms, and saturation
      int64_t out[2] = {static_cast<int64_t>(std::trunc(n[0])),
                        static_cast<int64_t>(std::trunc(n[1]))};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FDIVDrr: {  // fdiv dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n / m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FDIVSrr: {  // fdiv sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n / m, 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FDIVv2f64: {  // fdiv vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {n[0] / m[0], n[1] / m[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMADDDrrr: {  // fmadd dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(n, m, a), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMADDSrrr: {  // fmadd sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(n, m, a), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMAXNMDrr: {  // fmaxnm dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {std::fmax(n, m), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMAXNMv2f64: {  // fmaxnm vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {std::fmax(n[0], m[0]), std::fmax(n[1], m[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMAXNMPv2i64p: {  // fmaxnmp dd vd.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fmax(n[0], n[1]), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMINNMDrr: {  // fminnm dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {std::fmin(n, m), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMINNMv2f64: {  // fminnm vd.2d, vn.2d, vm.2d       
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {std::fmin(n[0], m[0]), std::fmin(n[1], m[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMINNMPv2i64p: {  // fminnmp dd vd.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {std::fmin(n[0], n[1]), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMLAv2f64: {  // fmla vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      const double* c = operands[2].getAsVector<double>();
      double out[2] = {a[0] + b[0] * c[0], a[1] + b[1] * c[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMLAv4f32: {  // fmla vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      const float* c = operands[2].getAsVector<float>();
      float out[4] = {a[0] + b[0] * c[0], a[1] + b[1] * c[1], 
                      a[2] + b[2] * c[2], a[3] + b[3] * c[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMLAv4i32_indexed: {  // fmla vd.4s, vn.4s, vm.s[index]
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      int index = metadata.operands[2].vector_index;
      const float c = operands[2].getAsVector<float>()[index];
      float out[4] = {a[0] + b[0] * c, a[1] + b[1] * c, 
                      a[2] + b[2] * c, a[3] + b[3] * c}; 
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMLSv4f32: {  // fmls vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      const float* c = operands[2].getAsVector<float>();
      float out[4] = {a[0] - b[0] * c[0], a[1] - b[1] * c[1], 
                      a[2] - b[2] * c[2], a[3] - b[3] * c[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMLSv4i32_indexed: {  // fmls vd.4s, vn.4s, vm.s[index]
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      int index = metadata.operands[2].vector_index;
      const float c = operands[2].getAsVector<float>()[index];
      float out[4] = {a[0] - b[0] * c, a[1] - b[1] * c, 
                      a[2] - b[2] * c, a[3] - b[3] * c};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVDXHighr: {  // fmov xd, vn.d[1]
      results[0] = operands[0].getAsVector<double>()[1];
      return;
    }
    case Opcode::AArch64_FMOVDXr: {  // fmov xd, dn
      results[0] = operands[0].get<double>();
      return;
    }
    case Opcode::AArch64_FMOVDi: {  // fmov dn, #imm
      double out[2] = {metadata.operands[1].fp, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVDr: {  // fmov dd, dn
      double out[2] = {operands[0].get<double>(), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVSWr: {  // fmov wd, sn
      results[0] = RegisterValue(operands[0].get<float>(), 8);
      return;
    }
    case Opcode::AArch64_FMOVSi: {  // fmov sn, #imm
      float out[4] = {static_cast<float>(metadata.operands[1].fp), 0.f, 0.f,
                      0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVSr: {  // fmov sd, sn
      float out[4] = {operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVWSr: {  // fmov sd, wn
      float out[4] = {operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVXDHighr: {  // fmov vd.d[1], xn
      double out[2] = {operands[0].get<double>(), operands[1].get<double>()};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVXDr: {  // fmov dd, xn
      double out[2] = {operands[0].get<double>(), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVv2f64_ns: {  // fmov vd.2d, #imm
      double out[2] = {metadata.operands[1].fp, metadata.operands[1].fp};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVv4f32_ns: {  // fmov vn.4s, #imm
      float imm = static_cast<float>(metadata.operands[1].fp);
      float out[4] = {imm, imm, imm, imm};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMSUBDrrr: {  // fmsub dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(-n, m, a), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMSUBSrrr: {  // fmsub sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(-n, m, a), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULDrr: {  // fmul dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n * m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULSrr: {  // fmul sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n * m, 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULv1i32_indexed: {  // fmul sd, sn, vm.s[index]
      int index = metadata.operands[2].vector_index;
      float n = operands[0].get<float>();
      float m = operands[1].getAsVector<float>()[index];
      float out[4] = {n * m, 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULv1i64_indexed: {  // fmul dd, dn, vm.d[index]
      int index = metadata.operands[2].vector_index;
      double n = operands[0].get<double>();
      double m = operands[1].getAsVector<double>()[index];
      double out[2] = {n * m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULv2f64: {  // fmul vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] * b[0], a[1] * b[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULv4f32: {  // fmul vd.4s, vn.4s, vm.4s
      const float* a = operands[0].getAsVector<float>();
      const float* b = operands[1].getAsVector<float>();
      float out[4] = {a[0] * b[0], a[1] * b[1], a[2] * b[2], a[3] * b[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMULv4i32_indexed: {  // fmul vd.4s, vn.4s, vm.s[index]
      int index = metadata.operands[2].vector_index;
      const float* a = operands[0].getAsVector<float>();
      const float b = operands[1].getAsVector<float>()[index];
      float out[4] = {a[0] * b, a[1] * b, a[2] * b, a[3] * b};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNEGDr: {  // fneg dd, dn
      double out[2] = {-operands[0].get<double>(), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNEGSr: {  // fneg sd, sn
      float out[4] = {-operands[0].get<float>(), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNEGv2f64: {  // fneg vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      double out[2] = {-n[0], -n[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNEGv4f32: {  // fneg vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {-n[0], -n[1], -n[2], -n[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNMSUBDrrr: {  // fnmsub dd, dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      double out[2] = {std::fma(n, m, -a), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FNMSUBSrrr: {  // fnmsub sd, sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      float out[4] = {std::fma(n, m, -a), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSQRTDr: {  // fsqrt dd, dn
      double out[2] = {::sqrt(operands[0].get<double>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSQRTSr: {  // fsqrt sd, sn
      float out[4] = {::sqrtf(operands[0].get<float>()), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSQRTv4f32: { // fsqrt vd.4s, vn.4s
      const float* n = operands[0].getAsVector<float>();
      float out[4] = {::sqrtf(n[0]), ::sqrtf(n[1]), ::sqrtf(n[2]), ::sqrtf(n[3])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSUBDrr: {  // fsub dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double out[2] = {n - m, 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSUBSrr: {  // fsub ss, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float out[4] = {n - m, 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSUBv2f64: {  // fsub vd.2d, vn.2d, vm.2d
      const double* n = operands[0].getAsVector<double>();
      const double* m = operands[1].getAsVector<double>();
      double out[2] = {n[0] - m[0], n[1] - m[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FSUBv4f32: {  // fsub vd.4s, vn.4s, vm.4s
      const float* n = operands[0].getAsVector<float>();
      const float* m = operands[1].getAsVector<float>();
      float out[4] = {n[0] - m[0], n[1] - m[1], n[2] - m[2], n[3] - m[3]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_LD1Rv4s: { // ld1r {vt.4s}, [xn]
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
    case Opcode::AArch64_LD1Twov16b: {  // ld1 {vt1.16b, vt2.16b}, [xn]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      return;
    }
    case Opcode::AArch64_LD1Twov16b_POST: {  // ld1 {vt1.16b, vt2.16b}, [xn],
                                             //   #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDAXRX: {  // ldaxr xd, [xn]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      return;
    }
    case Opcode::AArch64_LDPDpost: {  // ldp dt1, dt2, [xn], #imm
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_LDPDpre: {  // ldp dt1, dt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      results[1] = memoryData[1].zeroExtend(8, 16);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      return;
    }
    case Opcode::AArch64_LDPQpost: {  // ldp qt1, qt2, [xn], #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_LDPQpre: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_LDPSi: {  // ldp st1, st2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = memoryData[1].zeroExtend(4, 16);
      return;
    }
    case Opcode::AArch64_LDPWi: {  // ldp wt1, wt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = memoryData[1].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      return;
    }
    case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm]!
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRBBpost: {  // ldrb wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRBBroW: {  // ldrb wt,
                                      //  [xn, wm{, extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(1, 8);
      return;
    }
    case Opcode::AArch64_LDRBBroX: {  // ldrb wt,
                                      //  [xn, xm{, extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(1, 8);
      return;
    }
    case Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(1, 8);
      return;
    }
    case Opcode::AArch64_LDRDpost: {  // ldr dt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRDpre: {  // ldr dt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      return;
    }
    case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 16);
      return;
    }
    case Opcode::AArch64_LDRDui: {  // ldr dt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      return;
    }
    case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(2, 8);
      return;
    }
    case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(2, 8);
      return;
    }
    case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(2, 8);
      return;
    }
    case Opcode::AArch64_LDRQpost: {  // ldr qt, [xn], #imm
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend {#amount}}]
      results[0] = RegisterValue(static_cast<int32_t>(memoryData[0].get<int8_t>()), 4).zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
      results[0] = static_cast<int64_t>(memoryData[0].get<int8_t>());
      return;
    }
    case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend {#amount}}]
      results[0] = RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4).zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend {#amount}}]
      results[0] = RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4).zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRSHWui: {  // ldrsh wt, [xn, #imm]
      results[0] = RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4).zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      return;
    }
    case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      return;
    }
    case Opcode::AArch64_LDRSHXui: {  // ldrsh xt, [xn, #imm]
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      return;
    }
    case Opcode::AArch64_LDRSWpost: {  // ldrsw xt, [xn], #simm
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend {#amount}}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      return;
    }
    case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      return;
    }
    case Opcode::AArch64_LDRSpost: {  // ldr st, [xn], #imm
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRSpre: {  // ldr st, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(4, 16);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 16);
      return;
    }
    case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 16);
      return;
    }
    case Opcode::AArch64_LDRSui: {  // ldr st, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 16);
      return;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRWpre: {  // ldr wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRWroW: {  // ldr wt, [xn, wm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRWroX: {  // ldr wt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 8);
      return;
    }
    case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRXroW: {  // ldr xt, [xn, wn{, extend {#amount}}]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend {#amount}}]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(1, 8);
      return;
    }
    case Opcode::AArch64_LDURDi: {  // ldur dt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(8, 16);
      return;    
    }
    case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LSLVWr: {  // lslv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      results[0] = static_cast<uint64_t>(x << y);
      return;
    }
    case Opcode::AArch64_LSLVXr: {  // lslv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = x << y;
      return;
    }
    case Opcode::AArch64_LSRVWr: {  // lsrv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      results[0] = static_cast<uint64_t>(x >> y);
      return;
    }
    case Opcode::AArch64_LSRVXr: {  // lsrv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = x >> y;
      return;
    }
    case Opcode::AArch64_MADDXrrr: {  // madd xd, xn, xm, xa
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (x * y);
      return;
    }
    case Opcode::AArch64_MADDWrrr: {  // madd wd, wn, wm, wa
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      auto a = operands[2].get<uint32_t>();
      results[0] = static_cast<uint64_t>(a + (x * y));
      return;
    }
    case Opcode::AArch64_MOVID: {  // movi dd, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, 0};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MOVIv2d_ns: {  // movi vd.2d, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, bits};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MOVIv2i32: {  // movi vd.2s, #imm{, lsl #shift}
      uint32_t bits = shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, 0, 0};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MOVIv4i32: {  // movi vd.4s, #imm{, LSL #shift}
      uint32_t bits = shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, bits, bits};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MOVKWi: {  // movk wd, #imm
      // Clear 16-bit region offset by `shift` and replace with immediate
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t mask = ~(0xFFFF << shift);
      uint32_t value = (operands[0].get<uint32_t>() & mask) |
                       (metadata.operands[1].imm << shift);
      results[0] = RegisterValue(value, 8);
      return;
    }
    case Opcode::AArch64_MOVKXi: {  // movk xd, #imm
      // Clear 16-bit region offset by `shift` and replace with immediate
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t mask = ~(UINT64_C(0xFFFF) << shift);
      uint64_t value = (operands[0].get<uint64_t>() & mask) |
                       (metadata.operands[1].imm << shift);
      results[0] = value;
      return;
    }
    case Opcode::AArch64_MOVNWi: {  // movn wd, #imm{, LSL #shift}
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t value = ~(metadata.operands[1].imm << shift);
      results[0] = static_cast<uint64_t>(value);
      return;
    }
    case Opcode::AArch64_MOVNXi: {  // movn xd, #imm{, LSL #shift}
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t value = ~(metadata.operands[1].imm << shift);
      results[0] = value;
      return;
    }
    case Opcode::AArch64_MOVZWi: {  // movz wd, #imm
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t value = metadata.operands[1].imm << shift;
      results[0] = RegisterValue(value, 8);
      return;
    }
    case Opcode::AArch64_MOVZXi: {  // movz xd, #imm
      uint8_t shift = metadata.operands[1].shift.value;
      uint64_t value = metadata.operands[1].imm << shift;
      results[0] = value;
      return;
    }
    case Opcode::AArch64_MRS: {  // mrs xt, (systemreg|Sop0_op1_Cn_Cm_op2)
      results[0] = operands[0];
      return;
    }
    case Opcode::AArch64_MSR: {  // mrs (systemreg|Sop0_op1_Cn_Cm_op2), xt
      results[0] = operands[0];
      return;
    }
    case Opcode::AArch64_MSUBWrrr: {  // msub wd, wn, wm, wa
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      auto a = operands[2].get<uint32_t>();
      results[0] = RegisterValue(a - (x * y), 8);
      return;
    }
    case Opcode::AArch64_MSUBXrrr: {  // msub xd, xn, xm, xa
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      auto a = operands[2].get<uint64_t>();
      results[0] = a - (x * y);
      return;
    }
    case Opcode::AArch64_MVNIv2i32: {  // mvni vd.2s, #imm{, lsl #shift}
      uint32_t bits = ~shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, 0, 0};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MVNIv4i16: {  // mvni vd.4h, #imm{, lsl #shift}
      uint16_t bits = ~shiftValue(
          static_cast<uint16_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint16_t vector[8] = {bits, bits, bits, bits, 0, 0, 0, 0};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MVNIv4i32: {  // mvni vd.4s, #imm{, lsl #shift}
      uint32_t bits = ~shiftValue(
          static_cast<uint32_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint32_t vector[4] = {bits, bits, bits, bits};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_MVNIv8i16: {  // mvni vd.8h, #imm{, lsl #shift}
      uint16_t bits = ~shiftValue(
          static_cast<uint16_t>(metadata.operands[1].imm),
          metadata.operands[1].shift.type, metadata.operands[1].shift.value);
      uint16_t vector[8] = {bits, bits, bits, bits, bits, bits, bits, bits};
      results[0] = vector;
      return;
    }
    case Opcode::AArch64_HINT: {  // nop|yield|wfe|wfi|etc...
      // TODO: Observe hints
      return;
    }
    case Opcode::AArch64_ORNWrs: {  // orn wd, wn, wm{, shift{ #amount}}
      auto x = operands[0].get<uint32_t>();
      auto y = ~shiftValue(operands[1].get<uint32_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = RegisterValue(x | y, 8);
      return;
    }
    case Opcode::AArch64_ORNXrs: {  // orn xd, xn, xm{, shift{ #amount}}
      auto x = operands[0].get<uint64_t>();
      auto y = ~shiftValue(operands[1].get<uint64_t>(),
                           metadata.operands[2].shift.type,
                           metadata.operands[2].shift.value);
      results[0] = x | y;
      return;
    }
    case Opcode::AArch64_ORRWri: {  // orr wd, wn, #imm
      auto value = operands[0].get<uint32_t>();
      auto result = (value | static_cast<uint32_t>(metadata.operands[2].imm));
      results[0] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_ORRWrs: {  // orr wd, wn, wm{, shift{ #amount}}
      uint32_t result = operands[0].get<uint32_t>() |
                        shiftValue(operands[1].get<uint32_t>(),
                                   metadata.operands[2].shift.type,
                                   metadata.operands[2].shift.value);
      results[0] = static_cast<uint64_t>(result);
      return;
    }
    case Opcode::AArch64_ORRXri: {  // orr xd, xn, #imm
      auto value = operands[0].get<uint64_t>();
      auto result = value | metadata.operands[2].imm;
      results[0] = RegisterValue(result);
      return;
    }
    case Opcode::AArch64_ORRXrs: {  // orr xd, xn, xm{, shift{ #amount}}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x | y;
      return;
    }
    case Opcode::AArch64_ORRv16i8: {  // orr Vd.16b, Vn.16b, Vm.16b
      uint64_t out[2] = {operands[0].getAsVector<uint64_t>()[0] |
                             operands[1].getAsVector<uint64_t>()[0],
                         operands[0].getAsVector<uint64_t>()[1] |
                             operands[1].getAsVector<uint64_t>()[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      return;
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
      return;
    }
    case Opcode::AArch64_RET: {  // ret {xr}
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      return;
    }
    case Opcode::AArch64_REVXr: {  // rev xd, xn
      auto bytes = operands[0].getAsVector<uint8_t>();
      uint8_t reversed[8];
      // Copy `bytes` backwards onto `reversed`
      std::copy(bytes, bytes + 8, std::rbegin(reversed));
      results[0] = reversed;
      return;
    }
    case Opcode::AArch64_SBCWr: {  // sbc wd, wn, wm
      auto nzcv = operands[0].get<uint8_t>();
      auto x = operands[1].get<uint32_t>();
      auto y = operands[2].get<uint32_t>();
      uint32_t result;
      std::tie(result, std::ignore) = addWithCarry(x, ~y, (nzcv >> 1) & 1);
      results[0] = RegisterValue(result, 8);
      return;
    }
    case Opcode::AArch64_SBCXr: {  // sbc xd, xn, xm
      auto nzcv = operands[0].get<uint8_t>();
      auto x = operands[1].get<uint64_t>();
      auto y = operands[2].get<uint64_t>();
      uint64_t result;
      std::tie(result, std::ignore) = addWithCarry(x, ~y, (nzcv >> 1) & 1);
      results[0] = result;
      return;
    }
    case Opcode::AArch64_SBFMWri: {  // sbfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, 0u, r, s, true), 8);
      return;
    }
    case Opcode::AArch64_SBFMXri: {  // sbfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();
      results[0] = bitfieldManipulate(source, UINT64_C(0), r, s, true);
      return;
    }
    case Opcode::AArch64_SCVTFUWDri: {  // scvtf dd, wn
      double out[2] = {static_cast<double>(operands[0].get<int32_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFUWSri: {  // scvtf sd, wn
      int32_t n = operands[0].get<int32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFUXDri: {  // scvtf dd, xn
      double out[2] = {static_cast<double>(operands[0].get<int64_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFUXSri: {  // scvtf sd, xn
      int64_t n = operands[0].get<int64_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFv1i32: {  // scvtf sd, sn
      int32_t n = operands[0].get<int32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFv1i64: {  // scvtf dd, dn
      double out[2] = {static_cast<double>(operands[0].get<int64_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SCVTFv2f64: {  // scvtf vd.2d, vn.2d
      const int64_t* n = operands[0].getAsVector<int64_t>();      
      double out[2] = {static_cast<double>(n[0]),
                       static_cast<double>(n[1])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SDIVWr: {  // sdiv wd, wn, wm
      auto x = operands[0].get<int32_t>();
      auto y = operands[1].get<int32_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = RegisterValue(x / y, 8);
      }
      return;
    }
    case Opcode::AArch64_SDIVXr: {  // sdiv xd, xn, xm
      auto x = operands[0].get<int64_t>();
      auto y = operands[1].get<int64_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = x / y;
      }
      return;
    }
    case Opcode::AArch64_SHLd: {  // shl dd, dn #imm
      const uint64_t n = operands[0].get<uint64_t>();
      int64_t shift = metadata.operands[2].imm;
      uint64_t out[2] = {static_cast<uint64_t>(n << shift), 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SHLv4i32_shift: {  // shl vd.4s, vn.4s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      int64_t shift = metadata.operands[2].imm;
      uint32_t out[4] = {static_cast<uint32_t>(n[0] << shift),
                         static_cast<uint32_t>(n[1] << shift),
                         static_cast<uint32_t>(n[2] << shift),
                         static_cast<uint32_t>(n[3] << shift)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SMADDLrrr: {  // smaddl xd, wn, wm, xa
      auto n = static_cast<int64_t>(operands[0].get<int32_t>());
      auto m = static_cast<int64_t>(operands[1].get<int32_t>());
      auto a = operands[2].get<int64_t>();
      results[0] = a + (n * m);
      return;
    }
    case Opcode::AArch64_SMAXv4i32: {  // smax vd.4s, vn.4s, vm.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      const int32_t* m = operands[1].getAsVector<int32_t>();
      int32_t out[4] = {std::max(n[0], m[0]), std::max(n[1], m[1]),
                        std::max(n[2], m[2]), std::max(n[3], m[3])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SMINVv4i32v: {  // smin s0, vn.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      int32_t out = std::min(std::min(n[0], n[1]), std::min(n[2], n[3]));
      results[0] = RegisterValue(out, 16);
      return;
    }
    case Opcode::AArch64_SMINv4i32: {  // smin vd.4s, vn.4s, vm.4s
      const int32_t* n = operands[0].getAsVector<int32_t>();
      const int32_t* m = operands[1].getAsVector<int32_t>();
      int32_t out[4] = {std::min(n[0], m[0]), std::min(n[1], m[1]),
                        std::min(n[2], m[2]), std::min(n[3], m[3])};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SMULHrr: {  // smulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      // TODO: signed
      results[0] = mulhi(x, y);
      return;
    }
    case Opcode::AArch64_SSHLLv2i32_shift: {  // sshll vd.2d, vn.2s, #imm
      const int32_t* n = operands[0].getAsVector<int32_t>();
      int64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {static_cast<int64_t>(n[0] << shift),
                      static_cast<int64_t>(n[1] << shift)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SSHLLv4i32_shift: {  // sshll2 vd.2d, vn.4s, #imm
      const int32_t* n = operands[0].getAsVector<int32_t>();
      int64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {static_cast<int64_t>(n[2] << shift),
                      static_cast<int64_t>(n[3] << shift)};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_SSHRv4i32_shift: {  // sshr vd.4s, vn.4s, #imm
      const int32_t* n = operands[1].getAsVector<int32_t>();
      int64_t shift = metadata.operands[2].imm;
      int32_t out[4] = {static_cast<int32_t>(std::trunc(n[0] >> shift)),
                        static_cast<int32_t>(std::trunc(n[1] >> shift)),
                        static_cast<int32_t>(std::trunc(n[2] >> shift)),
                        static_cast<int32_t>(std::trunc(n[3] >> shift))};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_STLXRW: {  // stlxr ws, wt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      return;
    }
    case Opcode::AArch64_STLXRX: {  // stlxr ws, xt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      return;
    }
    case Opcode::AArch64_STPDi: {  // stp dt1, dt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case Opcode::AArch64_STPDpost: {  // stp dt1, dt2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_STPDpre: {  // stp dt1, dt2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_STPSi: {  // stp st1, st2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case Opcode::AArch64_STPSpost: {  // stp st1, st2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_STPSpre: {  // stp st1, st2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      return;
    }
    case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      return;
    }
    case Opcode::AArch64_STPWi: {  // stp wt1, wt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case Opcode::AArch64_STRBBpost: {  // strb wd, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRBBpre: {  // strb wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRBBroW: {  // strb wd,
                                      //  [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRBBroX: {  // strb wd,
                                      //  [xn, xm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRDpre: {  // str dd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRHHroW: {  // strh wd,
                                      //  [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRHHroX: {  // strh wd,
                                      //  [xn, xm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRQpost: {  // str qt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRSpost: {  // str st, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRSpre: {  // str sd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, #extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRSui: {  // str st, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRWpre: {  // str wd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRWroW: {  // str wd, [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      return;
    }
    case Opcode::AArch64_STRXpre: {  // str xd, [xn, #imm]!
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_STRXroW: {  // str xd, [xn, wm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend, {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURDi: {  // stur dt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURQi: {  // stur qt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURSi: {  // stur st, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STURXi: {  // stur xt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      return;
    }
    case Opcode::AArch64_SUBv4i32: {  // sub vd.4s, vn.4s, vm.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      const uint32_t* m = operands[1].getAsVector<uint32_t>();
      uint32_t out[4] = {n[0] - m[0], n[1] - m[1], n[2] - m[2], n[3] - m[3]};
      results[0] = out;
      return;
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
      return;
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
      return;
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
      return;
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
      return;
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
      return;
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
      return;
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
      return;
    }
    case Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y, 8);
      return;
    }
    case Opcode::AArch64_SUBWrs: {  // sub wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y, 8);
      return;
    }
    case Opcode::AArch64_SUBXri: {  // sub xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(static_cast<uint64_t>(metadata.operands[2].imm),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = RegisterValue(x - y);
      return;
    }
    case Opcode::AArch64_SUBXrs: {  // sub xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      results[0] = x - y;
      return;
    }
    case Opcode::AArch64_SUBXrx64: {  // sub xd, xn, xm{, extend #amount}
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x - y;
      return;
    }
    case Opcode::AArch64_SVC: {  // svc #imm
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      return;
    }
    case Opcode::AArch64_TBNZW: {  // tbnz wn, #imm, label
      if (operands[0].get<uint32_t>() & (1 << metadata.operands[1].imm)) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
    }
    case Opcode::AArch64_TBNZX: {  // tbnz xn, #imm, label
      if (operands[0].get<uint64_t>() & (1 << metadata.operands[1].imm)) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
    }
    case Opcode::AArch64_TBZW: {  // tbz wn, #imm, label
      if (operands[0].get<uint32_t>() & (1 << metadata.operands[1].imm)) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      }
      return;
    }
    case Opcode::AArch64_TBZX: {  // tbz xn, #imm, label
      if (operands[0].get<uint64_t>() & (1ul << metadata.operands[1].imm)) {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      } else {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[2].imm;
      }
      return;
    }
    case Opcode::AArch64_UBFMWri: {  // ubfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();
      results[0] = RegisterValue(bitfieldManipulate(source, 0u, r, s), 8);
      return;
    }
    case Opcode::AArch64_UBFMXri: {  // ubfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();
      results[0] = bitfieldManipulate(source, UINT64_C(0), r, s);
      return;
    }
    case Opcode::AArch64_UCVTFUWDri: {  // ucvtf dd, wn
      double out[2] = {static_cast<double>(operands[0].get<uint32_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UCVTFUWSri: {  // ucvtf sd, wn
      uint32_t n = operands[0].get<uint32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UCVTFUXDri: {  // ucvtf dd, xn
      double out[2] = {static_cast<double>(operands[0].get<uint64_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UCVTFUXSri: {  // ucvtf sd, xn
      uint64_t n = operands[0].get<uint64_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UCVTFv1i32: {  // ucvtf sd, sn
      uint32_t n = operands[0].get<uint32_t>();
      float out[4] = {static_cast<float>(n), 0.f, 0.f, 0.f};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UCVTFv1i64: {  // ucvtf dd, dn
      double out[2] = {static_cast<double>(operands[0].get<uint64_t>()), 0.0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_UDIVWr: {  // udiv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = RegisterValue(x / y, 8);
      }
      return;
    }
    case Opcode::AArch64_UDIVXr: {  // udiv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      if (y == 0) {
        results[0] = RegisterValue(0, 8);
      } else {
        results[0] = x / y;
      }
      return;
    }
    case Opcode::AArch64_UMADDLrrr: {  // umaddl xd, wn, wm, xa
      auto n = static_cast<uint64_t>(operands[0].get<uint32_t>());
      auto m = static_cast<uint64_t>(operands[1].get<uint32_t>());
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (n * m);
      return;
    }
    case Opcode::AArch64_UMOVvi32: {  // umov wd, vn.s[index]
      const uint32_t* vec = operands[0].getAsVector<uint32_t>();
      results[0] = RegisterValue(vec[metadata.operands[1].vector_index], 8);
      return;
    }
    case Opcode::AArch64_UMOVvi64: {  // umov xd, vn.d[index]
      const uint64_t* vec = operands[0].getAsVector<uint64_t>();
      results[0] = vec[metadata.operands[1].vector_index];
      return;
    }
    case Opcode::AArch64_UMULHrr: {  // umulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = mulhi(x, y);
      return;
    }
    case Opcode::AArch64_USHLLv4i16_shift: {  // ushll vd.4s, vn.4h, #imm
      const uint16_t* n = operands[0].getAsVector<uint16_t>();
      int64_t shift = metadata.operands[2].imm;
      uint16_t out[8] = {static_cast<uint16_t>(n[0] << shift), 0, 
                         static_cast<uint16_t>(n[1] << shift), 0,
                         static_cast<uint16_t>(n[2] << shift), 0, 
                         static_cast<uint16_t>(n[3] << shift), 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_XTNv2i32: {  // xtn vd.2s, vn.2d
      const uint64_t* n = operands[0].getAsVector<uint64_t>();
      uint32_t out[4] = {static_cast<uint32_t>(n[0]),
                         static_cast<uint32_t>(n[1]), 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_XTNv4i16: {  // xtn vd.4h, vn.4s
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint16_t out[8] = {static_cast<uint16_t>(n[0]),
                         static_cast<uint16_t>(n[1]),
                         static_cast<uint16_t>(n[2]),
                         static_cast<uint16_t>(n[3]), 0, 0, 0, 0};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_XTNv4i32: {  // xtn2 vd.4s, vn.2d
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* n = operands[1].getAsVector<uint64_t>();
      uint32_t out[4] = {d[0], d[1], static_cast<uint32_t>(n[0]),
                         static_cast<uint32_t>(n[1])};
      results[0] = out;
      return;
    }
    default:
      return executionNYI();
  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
