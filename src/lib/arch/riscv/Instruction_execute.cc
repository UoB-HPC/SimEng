#include <cmath>
#include <iostream>
#include <limits>
#include <tuple>

#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

uint8_t nzcv(bool n, bool z, bool c, bool v) {
  return (n << 3) | (z << 2) | (c << 1) | v;
}

/** Apply the shift specified by `shiftType` to the unsigned integer `value`,
 * shifting by `amount`. */
template <typename T>
std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T> shiftValue(
    T value, uint8_t shiftType, uint8_t amount) {
  switch (shiftType) {
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

/** Extend 'bits' by value in position 'msb' of 'bits' (1 indexed) */
uint64_t bitExtend(uint64_t bits, uint64_t msb) {
  int64_t leftShift = bits << (64 - msb);
  int64_t rightShift = leftShift >> (64 - msb);
  return rightShift;
}

uint64_t signExtendW(uint64_t bits) {
  return bitExtend(bits, 32);
}

uint64_t zeroExtend(uint64_t bits, uint64_t msb) {
  uint64_t leftShift = bits << (64 - msb);
  uint64_t rightShift = leftShift >> (64 - msb);
  return rightShift;
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

  std::cout << metadata.mnemonic << " " << metadata.operandStr << std::endl;

  //      std::cout << rs1 << ">>" << operands[1].get<uint32_t>() << std::endl;
//      std::cout << out << std::endl;
  //      std::cout << operands[0].get<uint64_t>() << "+" << metadata.operands[1].mem.disp << std::endl; std::cout << std::hex << results[0].get<uint64_t>() << std::dec << std::endl;

  executed_ = true;
  switch (metadata.opcode) {
    case Opcode::RISCV_BEQ: {  // Temporary syscall to get heap address
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      break;
    } case Opcode::RISCV_LB: {
      results[0] = bitExtend(memoryData[0].get<uint64_t>(), 8);
      break;
    } case Opcode::RISCV_LBU: {
      results[0] = zeroExtend(memoryData[0].get<uint64_t>(), 8);
      break;
    } case Opcode::RISCV_LH: {
      results[0] = bitExtend(memoryData[0].get<uint64_t>(), 16);
      break;
    } case Opcode::RISCV_LHU: {
      results[0] = zeroExtend(memoryData[0].get<uint64_t>(), 16);
      break;
    } case Opcode::RISCV_LW: {
      results[0] = bitExtend(memoryData[0].get<uint64_t>(), 32);
      break;
    } case Opcode::RISCV_LWU: {
      results[0] = zeroExtend(memoryData[0].get<uint64_t>(), 32);
      break;
    } case Opcode::RISCV_LD: {
      results[0] = memoryData[0];
      break;
    }
    case Opcode::RISCV_SB:
    case Opcode::RISCV_SH:
    case Opcode::RISCV_SW:
    case Opcode::RISCV_SD: {
      memoryData[0] = operands[0];
      break;
    } case Opcode::RISCV_SLL: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>() & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SLLI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = metadata.operands[2].imm & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SLLW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = operands[1].get<int32_t>() & 63; // Only use lowest 6 bits
      int64_t out = signExtendW(static_cast<int32_t>(rs1 << rs2));
      results[0] = out;
      break;
    } case Opcode::RISCV_SLLIW: {
      const int32_t rs1 = operands[0].get<uint32_t>();
      const int32_t rs2 = metadata.operands[2].imm & 63; // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 << rs2));
      results[0] = out;
      break;
    } case Opcode::RISCV_SRL: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>() & 63;  // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SRLI: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = metadata.operands[2].imm & 63; // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SRLW: {
      const uint32_t rs1 = operands[0].get<uint32_t>();
      const uint32_t rs2 = operands[1].get<uint32_t>() & 63; // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint64_t>(rs1 >> rs2));
      results[0] = out;
      break;
    } case Opcode::RISCV_SRLIW: {
      const uint32_t rs1 = operands[0].get<uint32_t>();
      const uint32_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 >> rs2));
      results[0] = out;
      break;
    } case Opcode::RISCV_SRA: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>() & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SRAI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = metadata.operands[2].imm & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SRAW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = operands[1].get<int32_t>() & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int32_t>(rs1 >> rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SRAIW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = metadata.operands[2].imm & 63; // Only use lowest 6 bits
      int64_t out = static_cast<int32_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }case Opcode::RISCV_ADD: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(n + m);
      results[0] = out;
      break;
    }case Opcode::RISCV_ADDW: {
      const int32_t n = operands[0].get<int32_t>();
      const int32_t m = operands[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(n + m));
      results[0] = out;
      break;
    } case Opcode::RISCV_ADDI: {  // addi ad, an, #imm
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(rs1 + rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SUB: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 - rs2);
      results[0] = out;
      break;
    } case Opcode::RISCV_SUBW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = operands[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(rs1 - rs2));
      results[0] = out;
      break;
    } case Opcode::RISCV_XOR: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m ^ n);
      results[0] = out;
      break;
    } case Opcode::RISCV_XORI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n ^ m);
      results[0] = out;
      break;
    } case Opcode::RISCV_OR: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m | n);
      results[0] = out;
      break;
    } case Opcode::RISCV_ORI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n | m);
      results[0] = out;
      break;
    } case Opcode::RISCV_AND: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m & n);
      results[0] = out;
      break;
    } case Opcode::RISCV_ANDI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n & m);
      results[0] = out;
      break;
    } case Opcode::RISCV_SLT: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>();
      if (rs1 < rs2) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    } case Opcode::RISCV_SLTU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 < rs2) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    } case Opcode::RISCV_SLTI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t imm = metadata.operands[2].imm;
      if (rs1 < imm) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    } case Opcode::RISCV_SLTIU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t imm = static_cast<int64_t>(metadata.operands[2].imm);
      if (rs1 < imm) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    } case Opcode::RISCV_JAL: {
      branchAddress_ = instructionAddress_ + metadata.operands[1].imm; // Set LSB of result to 0
      branchTaken_ = true; // TODO Jumps should not need the branch predictor
      results[0] = instructionAddress_ + 4;
      break;
    } case Opcode::RISCV_JALR: {
      branchAddress_ = (operands[0].get<uint64_t>() + metadata.operands[2].imm) & ~1; // Set LSB of result to 0
      branchTaken_ = true; // TODO Jumps should not need the branch predictor
      results[0] = instructionAddress_ + 4;
      break;
    }
    default:
      return executionNYI();
  }
  // Zero-out upper bits of vector registers because Z configuration
  // extend to 256 bytes whilst V configurations only extend to 16 bytes.
  // Thus upper 240 bytes must be ignored by being set to 0.
//  for (int i = 0; i < destinationRegisterCount; i++) {
//    if ((destinationRegisters[i].type == RegisterType::VECTOR) && !isSVE_) {
//      results[i] = results[i].zeroExtend(16, 256);
//    }
//  }
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng