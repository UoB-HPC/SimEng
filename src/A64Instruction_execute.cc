#include "A64Instruction.hh"

#include <iostream>
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
  exception = A64InstructionException::ExecutionNotYetImplemented;
  return;
}

void A64Instruction::execute() {
  assert(!executed && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  // std::cout << "Executing " << insn.mnemonic << " " << insn.op_str << " ("
  //           << insn.id << ")" << std::endl;
  executed = true;
  switch (insn.id) {
    case ARM64_INS_B: {
      if (sourceRegisterCount > 0) {  // B.cond
        if (conditionHolds(insn.detail.cc - 1, operands[0].get<uint8_t>())) {
          branchTaken = true;
          branchAddress = instructionAddress + insn.detail.operands[0].imm;
          // std::cout << "B.cond; relative: "
          //           << insn.detail->arm64.operands[0].imm
          //           << "; type: " << insn.detail->arm64.operands[0].type
          //           << std::endl;
        } else {
          branchTaken = false;
          branchAddress = instructionAddress + 4;
        }
      } else {
        branchTaken = true;
        branchAddress = instructionAddress + insn.detail.operands[0].imm;
      }
      return;
    }
    case ARM64_INS_ORR: {
      if (sourceRegisterCount > 1) {
        // Register, NYI
        return executionNYI();
      }
      switch (getRegisterSize(insn.detail.operands[0].reg)) {
        case A64RegisterSize::X: {
          auto value = operands[0].get<uint64_t>();
          auto result = value | insn.detail.operands[2].imm;
          results[0] = RegisterValue(result);
          return;
        }
        case A64RegisterSize::W: {
          auto value = operands[0].get<uint32_t>();
          auto result =
              (value | static_cast<uint32_t>(insn.detail.operands[2].imm));
          results[0] = RegisterValue(result, 8);
          return;
        }
        default:
          return executionNYI();
      }
    }
    case ARM64_INS_SUB: {
      if (sourceRegisterCount > 1) {  // Register, NYI
        return executionNYI();
      }
      if (destinationRegisterCount > 1) {  // SUBS
        switch (getRegisterSize(insn.detail.operands[0].reg)) {
          case A64RegisterSize::X: {
            auto x = operands[0].get<uint64_t>();
            auto y = ~(insn.detail.operands[2].imm);
            auto [result, nzcv] = addWithCarry(x, y, true);
            results[0] = RegisterValue(nzcv);
            results[1] = RegisterValue(result);
            return;
          }
          case A64RegisterSize::W: {
            auto x = operands[0].get<uint32_t>();
            auto y = ~static_cast<uint32_t>(insn.detail.operands[2].imm);
            auto [result, nzcv] = addWithCarry(x, y, true);
            results[0] = RegisterValue(nzcv);
            results[1] = RegisterValue(result, 8);
            // std::cout << "SUBS; op = " << operands[0].get<uint32_t>()
            //           << "; imm = " << insn.detail->arm64.operands[2].imm
            //           << "; result = " << result << "; nzcv = " << (int)nzcv
            //           << std::endl;
            return;
          }
          default:
            return executionNYI();
        }
      }
    }
    default:
      return executionNYI();
  }

  // switch (opcode) {
  //   case A64Opcode::ADD_I: {
  //     if (metadata.sf) {
  //       auto x = operands[0].get<uint64_t>();
  //       auto y = metadata.imm;
  //       results[0] = RegisterValue(x + y);
  //     } else {
  //       auto x = operands[0].get<uint32_t>();
  //       auto y = static_cast<uint32_t>(metadata.imm);
  //       results[0] = RegisterValue(x + y, 8);
  //     }
  //     return;
  //   }
  //   case A64Opcode::B: {
  //     branchTaken = true;
  //     branchAddress = instructionAddress + metadata.offset;
  //     return;
  //   }
  //   case A64Opcode::B_cond: {
  //     if (conditionHolds(metadata.cond, operands[0].get<uint8_t>())) {
  //       branchTaken = true;
  //       branchAddress = instructionAddress + metadata.offset;
  //     } else {
  //       branchTaken = false;
  //       branchAddress = instructionAddress + 4;
  //     }
  //     return;
  //   }
  //   case A64Opcode::LDR_I: {
  //     results[0] = memoryData[0].zeroExtend(memoryAddresses[0].second,
  //     8); return;
  //   }
  //   case A64Opcode::ORR_I: {
  //     if (metadata.sf) {
  //       auto value = operands[0].get<uint64_t>();
  //       auto result = value | metadata.imm;
  //       results[0] = RegisterValue(result);
  //     } else {
  //       auto value = operands[0].get<uint32_t>();
  //       auto result = (value | static_cast<uint32_t>(metadata.imm));
  //       results[0] = RegisterValue(result, 8);
  //     }
  //     return;
  //   }
  //   case A64Opcode::STR_I: {
  //     memoryData[0] = operands[0];
  //     return;
  //   }
  //   case A64Opcode::SUB_Shift: {
  //     if (metadata.sf) {
  //       auto x = operands[0].get<uint64_t>();
  //       auto y = operands[1].get<uint64_t>();
  //       results[0] = RegisterValue(x - y);
  //     } else {
  //       auto x = operands[0].get<uint32_t>();
  //       auto y = operands[1].get<uint32_t>();
  //       results[0] = RegisterValue(x - y, 8);
  //     }
  //     return;
  //   }
  //   case A64Opcode::SUB_I: {
  //     if (metadata.sf) {
  //       auto x = operands[0].get<uint64_t>();
  //       auto y = metadata.imm;
  //       results[0] = RegisterValue(x - y);
  //     } else {
  //       auto x = operands[0].get<uint32_t>();
  //       auto y = static_cast<uint32_t>(metadata.imm);
  //       results[0] = RegisterValue(x - y, 8);
  //     }
  //     return;
  //   }
  //   case A64Opcode::SUBS_I: {
  //     if (metadata.sf) {
  //       auto x = operands[0].get<uint64_t>();
  //       auto y = ~metadata.imm;
  //       auto [result, nzcv] = addWithCarry(x, y, true);
  //       results[0] = RegisterValue(result);
  //       results[1] = RegisterValue(nzcv);
  //     } else {
  //       auto x = operands[0].get<uint32_t>();
  //       auto y = ~static_cast<uint32_t>(metadata.imm);
  //       auto [result, nzcv] = addWithCarry(x, y, true);
  //       results[0] = RegisterValue(result, 8);
  //       results[1] = RegisterValue(nzcv);
  //     }
  //     return;
  //   }
  //   case A64Opcode::TBNZ: {
  //     uint64_t x = operands[0].get<uint64_t>();
  //     uint64_t mask = 1 << (metadata.bitPos - 1);
  //     if ((x & mask)) {
  //       branchTaken = true;
  //       branchAddress = instructionAddress + metadata.offset;
  //     } else {
  //       branchTaken = false;
  //       branchAddress = instructionAddress + 4;
  //     }
  //     return;
  //   }
  //   default:
  //     exception = A64InstructionException::ExecutionNotYetImplemented;
  //     return;
  // }
}

}  // namespace simeng
