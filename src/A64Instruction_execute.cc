#include "A64Instruction.hh"
#include "A64InstructionMetadata.hh"

#include <cmath>
#include <limits>
#include <tuple>

uint8_t nzcv(bool n, bool z, bool c, bool v) {
  return (n << 3) | (z << 2) | (c << 1) | v;
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
    c = ((std::numeric_limits<uint64_t>::max() - x - carryIn) > y);
  }

  bool v = ((x < 0) != (result < 0));

  return {result, nzcv(n, z, c, v)};
}
std::tuple<uint32_t, uint8_t> addWithCarry(uint32_t x, uint32_t y,
                                           bool carryIn) {
  uint64_t unsignedResult =
      static_cast<uint64_t>(x) + static_cast<int64_t>(y) + carryIn;
  int32_t result = static_cast<int32_t>(x) + static_cast<int32_t>(y) + carryIn;
  bool n = (result < 0);
  bool z = (result == 0);

  bool c = unsignedResult != static_cast<uint64_t>(result);

  bool v = ((x < 0) != (result < 0));

  return {result, nzcv(n, z, c, v)};
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
      result = (c && !v);
      break;  // HI/LS
    case 0b101:
      result = (n == v);
      break;  // GE/LT
    case 0b110:
      result = (n == v && z);
      break;  // GT/LE
    default:  // 0b111, AL
      result = true;
  }

  return (inverse ? !result : result);
}

namespace simeng {

void A64Instruction::executionNYI() {
  exceptionEncountered_ = true;
  exception = A64InstructionException::ExecutionNotYetImplemented;
  return;
}

void A64Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  executed_ = true;
  switch (metadata.opcode) {
    case A64Opcode::AArch64_ADDWri: {  // add wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      results[0] = RegisterValue(x + y, 8);
      return;
    }
    case A64Opcode::AArch64_ADDXri: {  // add xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      results[0] = RegisterValue(x + y);
      return;
    }
    case A64Opcode::AArch64_ADRP: {  // adrp xd, #imm
      // Clear lowest 12 bits of address and add immediate (already shifted by
      // decoder)
      results[0] = (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
      return;
    }
    case A64Opcode::AArch64_B: {  // b label
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      return;
    }
    case A64Opcode::AArch64_Bcc: {  // b.cond label
      if (conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      return;
    }
    case A64Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] + b[0], a[1] + b[1]};
      results[0] = out;
      return;
    }
    case A64Opcode::AArch64_FCMPDri: {  // fcmp dn, #imm
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
    case A64Opcode::AArch64_FCMPDrr: {  // fcmp dn, dm
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
    case A64Opcode::AArch64_FMOVv2f64_ns: {  // fmov vd.2d, #imm
      double out[2] = {metadata.operands[0].fp, metadata.operands[0].fp};
      results[0] = out;
      return;
    }
    case A64Opcode::AArch64_FMULv2f64: {  // fmul vd.2d, vn.2d, vm.2d
      const double* a = operands[0].getAsVector<double>();
      const double* b = operands[1].getAsVector<double>();
      double out[2] = {a[0] * b[0], a[1] * b[1]};
      results[0] = out;
      return;
    }
    case A64Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].second, 16);
      results[1] = memoryData[1].zeroExtend(memoryAddresses[1].second, 16);
      return;
    }
    case A64Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm, {extend {#amount}}]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].second, 16);
      return;
    }
    case A64Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].second, 8);
      return;
    }
    case A64Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      results[0] = memoryData[0];
      return;
    }
    case A64Opcode::AArch64_MOVIv2d_ns: {  // movi vd.2d, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t vector[2] = {bits, bits};
      results[0] = vector;
      return;
    }
    case A64Opcode::AArch64_MOVKWi: {  // movk wd, #imm
      // Clear 16-bit region offset by `shift` and replace with immediate
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t mask = ~(0xFFFF << shift);
      uint32_t value = (operands[0].get<uint32_t>() & mask) |
                       (metadata.operands[1].imm << shift);
      results[0] = RegisterValue(value, 8);
      return;
    }
    case A64Opcode::AArch64_MOVZWi: {  // movk wd, #imm
      uint8_t shift = metadata.operands[1].shift.value;
      uint32_t value = metadata.operands[1].imm << shift;
      results[0] = RegisterValue(value, 8);
      return;
    }
    case A64Opcode::AArch64_ORRWri: {  // orr wd, wn, #imm
      auto value = operands[0].get<uint32_t>();
      auto result = (value | static_cast<uint32_t>(metadata.operands[2].imm));
      results[0] = RegisterValue(result, 8);
      return;
    }
    case A64Opcode::AArch64_ORRXri: {  // orr xd, xn, #imm
      auto value = operands[0].get<uint64_t>();
      auto result = value | metadata.operands[2].imm;
      results[0] = RegisterValue(result);
      return;
    }
    case A64Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      return;
    }
    case A64Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case A64Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      memoryData[0] = operands[0];
      return;
    }
    case A64Opcode::AArch64_SUBSWri: {  // subs wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = ~static_cast<uint32_t>(metadata.operands[2].imm);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result, 8);
      return;
    }
    case A64Opcode::AArch64_SUBSXri: {  // subs xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = ~(metadata.operands[2].imm);
      auto [result, nzcv] = addWithCarry(x, y, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result);
      return;
    }
    case A64Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm
      auto x = operands[0].get<uint32_t>();
      auto y = static_cast<uint32_t>(metadata.operands[2].imm);
      results[0] = RegisterValue(x - y, 8);
      return;
    }
    case A64Opcode::AArch64_SUBXri: {  // sub xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = metadata.operands[2].imm;
      results[0] = RegisterValue(x - y);
      return;
    }
    default:
      return executionNYI();
  }
}

}  // namespace simeng
