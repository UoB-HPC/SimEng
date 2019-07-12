#include "Instruction.hh"
#include "InstructionMetadata.hh"

#include <cmath>
#include <limits>
#include <tuple>

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
bitfieldManipulate(T value, uint8_t rotateBy, uint8_t sourceBits,
                   bool signExtend = false) {
  T mask = (1 << sourceBits) - 1;
  T source = value & mask;
  size_t bits = sizeof(T) * 8;

  T result;
  uint8_t highestBit = sourceBits;
  if (sourceBits >= rotateBy) {
    // Mask of values [rotateBy:source+1]
    result = source >> rotateBy;
    highestBit -= rotateBy;
  } else {
    result = source << (bits - rotateBy);
    highestBit += (bits - rotateBy);
  }

  if (!signExtend) {
    return result;
  }

  if (highestBit > bits) {
    // Nothing to do; implicitly sign-extended
    return result;
  }

  // Let the compiler do sign-extension for us.
  uint8_t shiftAmount = bits - highestBit;
  // Shift the bitfield up, and cast to a signed type, so the highest bit is now
  // the sign bit
  auto shifted = static_cast<std::make_signed_t<T>>(result << shiftAmount);
  // Shift the bitfield back to where it was; as it's a signed type, the
  // compiler will sign-extend the highest bit
  return shifted >> shiftAmount;
}

std::tuple<uint64_t, uint8_t> addWithCarry(uint64_t x, uint64_t y,
                                           bool carryIn) {
  int64_t result = static_cast<int64_t>(x) + static_cast<int64_t>(y) + carryIn;
  bool n = (result < 0);
  bool z = (result == 0);

  // Trying to calculate whether `result` overflows (`x + y + carryIn > max`).
  bool c;
  if (carryIn && x + 1 == 0) {
    // Implies `x` is max; with a carry set, it will definitely overflow
    c = true;
  } else {
    // We know x + carryIn <= max, so can safely subtract and compare against y
    // max > x + y + c == max - x > y + c
    c = ((std::numeric_limits<uint64_t>::max() - x - carryIn) < y);
  }

  bool v = (std::numeric_limits<int64_t>::max() - static_cast<int64_t>(x) -
            carryIn) < static_cast<int32_t>(y);

  return {result, nzcv(n, z, c, v)};
}
std::tuple<uint32_t, uint8_t> addWithCarry(uint32_t x, uint32_t y,
                                           bool carryIn) {
  uint64_t unsignedResult =
      static_cast<uint64_t>(x) + static_cast<uint64_t>(y) + carryIn;
  int64_t signedResult =
      static_cast<int64_t>(x) + static_cast<int64_t>(y) + carryIn;
  int32_t result = static_cast<int32_t>(x) + static_cast<int32_t>(y) + carryIn;
  bool n = (result < 0);
  bool z = (result == 0);

  bool c = unsignedResult != static_cast<uint32_t>(result);

  bool v = result != signedResult;

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
  exception = InstructionException::ExecutionNotYetImplemented;
  return;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  executed_ = true;
  switch (metadata.opcode) {
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
    case Opcode::AArch64_ADDWri: {  // add wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
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
    case Opcode::AArch64_ADDXri: {  // add xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
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
    case Opcode::AArch64_ADRP: {  // adrp xd, #imm
      // Clear lowest 12 bits of address and add immediate (already shifted by
      // decoder)
      results[0] = (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
      return;
    }
    case Opcode::AArch64_ANDSWrs: {  // ands wd, wn, wm{, shift #amount}
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(operands[1].get<uint32_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      uint32_t result = x & y;
      results[0] =
          nzcv(static_cast<int32_t>(result) < 0, result == 0, false, false);
      if (destinationRegisterCount > 1) {
        results[1] = static_cast<uint64_t>(result);
      }
      return;
    }
    case Opcode::AArch64_ANDSXri: {  // ands xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      uint64_t result = x & y;
      results[0] =
          nzcv(static_cast<int64_t>(result) < 0, result == 0, false, false);
      results[1] = result;
      return;
    }
    case Opcode::AArch64_ANDSXrs: {  // ands xd, xn, xm{, shift #amount}
      auto x = operands[0].get<uint64_t>();
      auto y = shiftValue(operands[1].get<uint64_t>(),
                          metadata.operands[2].shift.type,
                          metadata.operands[2].shift.value);
      uint64_t result = x & y;
      results[0] =
          nzcv(static_cast<int64_t>(result) < 0, result == 0, false, false);
      if (destinationRegisterCount > 1) {
        results[1] = result;
      }
      return;
    }
    case Opcode::AArch64_ANDWri: {  // and wd, xn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
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
    case Opcode::AArch64_B: {  // b label
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
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
        std::tie(std::ignore, nzcv) = addWithCarry(
            operands[1].get<uint32_t>(), ~metadata.operands[1].imm, 1);
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
        std::tie(std::ignore, nzcv) = addWithCarry(
            operands[1].get<uint64_t>(), ~metadata.operands[1].imm, 1);
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
    case Opcode::AArch64_DUPv16i8gpr: {  // dup vd.16b, wn
      uint8_t out[16];
      std::fill(std::begin(out), std::end(out), operands[0].get<uint8_t>());
      results[0] = out;
      return;
    }
    case Opcode::AArch64_DMB: {  // dmb option|#imm
      // TODO: Respect memory barriers
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
    case Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] + b[0], a[1] + b[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FCMPDri: {  // fcmp dn, #imm
      double a = operands[0].get<double>();
      double b = metadata.operands[1].fp;
      if (std::isnan(a) || std::isnan(b)) {
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
    case Opcode::AArch64_FCMPDrr: {  // fcmp dn, dm
      double a = operands[0].get<double>();
      double b = operands[1].get<double>();
      if (std::isnan(a) || std::isnan(b)) {
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
    case Opcode::AArch64_FMLAv2f64: {  // fmla vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[0].getAsVector<double>();
      const double* c = operands[0].getAsVector<double>();
      double out[2] = {a[0] + b[0] * c[0], a[1] + b[1] * c[1]};
      results[0] = out;
      return;
    }
    case Opcode::AArch64_FMOVv2f64_ns: {  // fmov vd.2d, #imm
      double out[2] = {metadata.operands[0].fp, metadata.operands[0].fp};
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
    case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      results[0] = memoryData[0].zeroExtend(4, 8);
      return;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0];
      results[1] = memoryData[1];
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
    }
    case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      return;
    }
    case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(2, 8);
      return;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0];
      return;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend, {#amount}}]
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
    case Opcode::AArch64_MADDXrrr: {  // madd xd, xn, xm, xa
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (x * y);
      return;
    }
    case Opcode::AArch64_MOVIv2d_ns: {  // movi vd.2d, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, bits};
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
      uint64_t mask = ~(0xFFFF << shift);
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
      // TODO: Correct system register read support
      uint64_t sysreg = static_cast<uint64_t>(metadata.operands[1].reg);
      switch (sysreg) {
        case ARM64_SYSREG_DCZID_EL0:
          // Temporary: state that DCZ can support clearing 64 bytes at a time,
          // but is disabled due to bit 4 being set
          results[0] = static_cast<uint64_t>(0b10100);
          return;
        case 0xde82:  // TPIDR_EL0
          // Temporary: return known Thread-Local Storage (TLS) address for test
          // file; remove once system register read/write is in place
          results[0] = static_cast<uint64_t>(0x493d40);
          return;
      }
      results[0] = static_cast<uint64_t>(0);
      return;
    }
    case Opcode::AArch64_MSR: {  // mrs (systemreg|Sop0_op1_Cn_Cm_op2), xt
      // TODO: Correct system register write support
      return;
    }
    case Opcode::AArch64_HINT: {  // nop|yield|wfe|wfi|etc...
      // TODO: Observe hints
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
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
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
    case Opcode::AArch64_SBFMWri: {  // sbfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();

      results[0] =
          static_cast<uint64_t>(bitfieldManipulate(source, r, s, true));
      return;
    }
    case Opcode::AArch64_SBFMXri: {  // sbfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();

      results[0] = bitfieldManipulate(source, r, s, true);
      return;
    }
    case Opcode::AArch64_STLXRW: {  // stlxr ws, wt, [xn]
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
    case Opcode::AArch64_STRBBroX: {  // strb wd,
                                      //  [xn, xm{, extend {#amount}}]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      memoryData[0] = operands[0];
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
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
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
    case Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
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
        results[1] = RegisterValue(result);
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
    case Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = shiftValue(static_cast<uint32_t>(metadata.operands[2].imm),
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
    case Opcode::AArch64_SUBXrx64: {
      auto x = operands[0].get<uint64_t>();
      auto y =
          extendValue(operands[1].get<uint64_t>(), metadata.operands[2].ext,
                      metadata.operands[2].shift.value);
      results[0] = x - y;
      return;
    }
    case Opcode::AArch64_SVC: {  // svc #imm
      exceptionEncountered_ = true;
      exception = InstructionException::SupervisorCall;
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
    case Opcode::AArch64_UBFMWri: {  // ubfm wd, wn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint32_t source = operands[0].get<uint32_t>();

      results[0] = static_cast<uint64_t>(bitfieldManipulate(source, r, s));
      return;
    }
    case Opcode::AArch64_UBFMXri: {  // ubfm xd, xn, #immr, #imms
      uint8_t r = metadata.operands[2].imm;
      uint8_t s = metadata.operands[3].imm;
      uint64_t source = operands[0].get<uint64_t>();

      results[0] = bitfieldManipulate(source, r, s);
      return;
    }
    case Opcode::AArch64_UDIVXr: {  // udiv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = x / y;
      return;
    }
    case Opcode::AArch64_UMULHrr: {  // umulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = mulhi(x, y);
      return;
    }
    default:
      return executionNYI();
  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
