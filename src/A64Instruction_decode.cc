#include <iostream>
#include "A64Instruction.hh"

#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {

/********************
 * HELPER FUNCTIONS
 *******************/

// Extract bit `start` of `value`
constexpr bool bit(uint32_t value, uint8_t start) {
  return (value >> start) & 1;
}
// Extract bits `start` to `start+width` of `value`
constexpr uint32_t bits(uint32_t value, uint8_t start, uint8_t width) {
  return ((value >> start) & ((1 << width) - 1));
}

// Generate a general purpose register identifier with tag `tag`
constexpr Register genReg(uint16_t tag) {
  return {A64RegisterType::GENERAL, tag};
}
// Generate a NZCV register identifier
constexpr Register nzcvReg() { return {A64RegisterType::NZCV, 0}; }

// Sign-extend a bitstring of length `currentLength`
constexpr int32_t signExtend(uint32_t value, int currentLength) {
  uint32_t mask = (-1) << currentLength;
  bool negative = bit(value, currentLength - 1);
  return static_cast<int32_t>(value) | (negative ? mask : 0);
}

/** Parses the Capstone `arm64_reg` value to generate an architectural register
 * representation.
 *
 * WARNING: this conversion is FRAGILE, and relies on the structure of the
 * `arm64_reg` enum. Updates to the Capstone library version may cause this to
 * break. */
Register csRegToRegister(arm64_reg reg) {
  // Check from top of the range downwards

  // ARM64_REG_X0 -> {end} are 64-bit (X) registers, reading from the general
  // file
  if (reg >= ARM64_REG_X0) {
    return {A64RegisterType::GENERAL,
            static_cast<uint16_t>(reg - ARM64_REG_X0)};
  }

  // ARM64_REG_V0 -> +31 are vector registers, reading from the vector file
  if (reg >= ARM64_REG_V0) {
    return {A64RegisterType::VECTOR, static_cast<uint16_t>(reg - ARM64_REG_V0)};
  }

  // ARM64_REG_W0 -> +30 are 32-bit (W) registers, reading from the general
  // file. Excludes #31 (WZR/WSP).
  if (reg >= ARM64_REG_W0) {
    return {A64RegisterType::GENERAL,
            static_cast<uint16_t>(reg - ARM64_REG_W0)};
  }

  // ARM64_REG_B0 and above are repeated ranges representing scalar access
  // specifiers on the vector registers (i.e., B, H, S, D, Q), each covering 32
  // registers
  if (reg >= ARM64_REG_B0) {
    return {A64RegisterType::VECTOR,
            static_cast<uint16_t>((reg - ARM64_REG_B0) % 32)};
  }

  // ARM64_REG_WZR and _XZR are zero registers, and don't read
  if (reg == ARM64_REG_WZR || reg == ARM64_REG_XZR) {
    return A64Instruction::ZERO_REGISTER;
  }

  // ARM64_REG_SP and _WSP are stack pointer registers, stored in r31 of the
  // general file
  if (reg == ARM64_REG_SP || reg == ARM64_REG_WSP) {
    return {A64RegisterType::GENERAL, 31};
  }

  // ARM64_REG_NZCV is the condition flags register
  if (reg == ARM64_REG_NZCV) {
    return {A64RegisterType::NZCV, 0};
  }
  // ARM64_REG_X29 is the frame pointer, stored in r29 of the general file
  if (reg == ARM64_REG_X29) {
    return {A64RegisterType::GENERAL, 29};
  }
  // ARM64_REG_X30 is the link register, stored in r30 of the general file
  if (reg == ARM64_REG_X30) {
    return {A64RegisterType::GENERAL, 30};
  }

  return {std::numeric_limits<uint8_t>::max(),
          std::numeric_limits<uint16_t>::max()};
}

A64RegisterSize A64Instruction::getRegisterSize(arm64_reg reg) const {
  if (reg >= ARM64_REG_X0) return A64RegisterSize::X;
  if (reg >= ARM64_REG_V0) return A64RegisterSize::V;
  if (reg >= ARM64_REG_W0) return A64RegisterSize::W;
  if (reg >= ARM64_REG_S0) return A64RegisterSize::S;
  if (reg >= ARM64_REG_Q0) return A64RegisterSize::Q;
  if (reg >= ARM64_REG_H0) return A64RegisterSize::H;
  if (reg >= ARM64_REG_D0) return A64RegisterSize::D;
  if (reg >= ARM64_REG_B0) return A64RegisterSize::B;
  if (reg == ARM64_REG_XZR) return A64RegisterSize::X;
  if (reg == ARM64_REG_WZR || reg == ARM64_REG_WSP) return A64RegisterSize::W;
  if (reg == ARM64_REG_NZCV) return A64RegisterSize::Cond;
  return A64RegisterSize::X;
}

// Check for and mark WZR/XZR references
const Register& filterZR(const Register& reg) {
  return (reg.type == A64RegisterType::GENERAL && reg.tag == 31
              ? A64Instruction::ZERO_REGISTER
              : reg);
}

uint64_t decodeBitMasks(uint8_t immN, uint8_t imms, uint8_t immr,
                        bool immediate, int size) {
  if (immN) {
    std::cout << "immN immediate decode unsupported" << std::endl;
    exit(1);
  }

  // Partial 32-bit only implementation;
  // `imms` specifies the number of ones
  // `immr` specifies the number of bits it's rotated to the right

  uint64_t welem = ONES(imms + 1);
  uint64_t wmask = ROR(welem, immr, size);
  return wmask;

  // TODO: Fully implement 32/64-bit implementation (partial implementation
  // below).

  // auto len = highestSetBit(CONCAT(immN, NOT(imms, 6), 6));
  // // if (len < 1) exit(418);
  // auto levels = 1 << (len - 1);
  // // if (immediate)
  // auto S = imms & levels;
  // auto R = immr & levels;
  // auto diff = S - R;
  // auto esize = ONES(len);

  // uint64_t welem = ONES(S + 1);
  // uint64_t wmask = ROR(welem, R);
}

/******************
 * DECODING LOGIC
 *****************/
void A64Instruction::decode() {
  std::cout << "Sizes: A64Instruction = " << sizeof(A64Instruction)
            << std::endl;

  // Extract implicit writes
  for (size_t i = 0; i < insn.regs_write_count; i++) {
    destinationRegisters[destinationRegisterCount] =
        csRegToRegister(static_cast<arm64_reg>(insn.regs_write[i]));
    destinationRegisterCount++;
  }
  // Extract implicit reads
  for (size_t i = 0; i < insn.regs_read_count; i++) {
    sourceRegisters[sourceRegisterCount] =
        csRegToRegister(static_cast<arm64_reg>(insn.regs_read[i]));
    sourceRegisterCount++;
    operandsPending++;
  }

  // Extract explicit register accesses
  for (size_t i = 0; i < insn.detail.op_count; i++) {
    const auto& op = insn.detail.operands[i];
    if (op.type != ARM64_OP_REG) {
      // Only check op registers
      continue;
    }

    if (op.access & cs_ac_type::CS_AC_WRITE) {
      // Add register writes to destinations
      destinationRegisters[destinationRegisterCount] = csRegToRegister(op.reg);
      destinationRegisterCount++;
    }
    if (op.access & cs_ac_type::CS_AC_READ) {
      // Add register reads to destinations
      sourceRegisters[sourceRegisterCount] = csRegToRegister(op.reg);
      if (sourceRegisters[sourceRegisterCount] ==
          A64Instruction::ZERO_REGISTER) {
        // Catch zero register references and pre-complete those operands
        operands[sourceRegisterCount] = RegisterValue(0, 8);
      } else {
        operandsPending++;
      }
      sourceRegisterCount++;
    }
  }

  // Identify branches
  for (size_t i = 0; i < insn.groups_count; i++) {
    if (insn.groups[i] == ARM64_GRP_JUMP) {
      isBranch_ = true;
    }
  }
}

void A64Instruction::decodeA64(uint32_t insn) {
  uint8_t op0 = (insn >> 25) & 0b1111;
  uint8_t op0_1 = (op0 >> 1) & 1;
  uint8_t op0_2 = (op0 >> 2) & 1;

  if (op0_2) {
    bool op0_0 = op0 & 1;
    if (op0_0) {
      if (op0_1) {
        // Data Processing -- Scalar Floating Point and Advanced SIMD
        return decodeA64DataFPSIMD(insn);
      }
      // Data Processing -- Register
      return decodeA64DataRegister(insn);
    }
    // Loads and Stores
    return decodeA64LoadStore(insn);
  }

  bool op0_3 = (op0 >> 3) & 1;
  if (op0_3) {
    if (op0_1) {
      // Branches, Exception Generating and System instructions
      return decodeA64BranchSystem(insn);
    }
    // Data Processing -- Immediate
    return decodeA64DataImmediate(insn);
  }

  // Unallocated group
  return unallocated();
}

void A64Instruction::nyi() {
  exception = A64InstructionException::EncodingNotYetImplemented;
}
void A64Instruction::unallocated() {
  exception = A64InstructionException::EncodingUnallocated;
}

void A64Instruction::decodeA64DataImmediate(uint32_t insn) {
  uint8_t op0 = bits(insn, 23, 3);
  switch (op0) {
    case 0b010:
      [[fallthrough]];
    case 0b011: {  // Add/subtract (immediate)
      auto shift = bits(insn, 22, 2);
      if (shift >= 0b10) {
        return unallocated();
      }

      auto sf = bit(insn, 31);
      auto op = bit(insn, 30);
      auto S = bit(insn, 29);
      auto Rd = bits(insn, 0, 5);
      auto Rn = bits(insn, 5, 5);
      auto imm = bits(insn, 10, 12);

      if (op) {  // SUB(S)
        opcode = (S ? A64Opcode::SUBS_I : A64Opcode::SUB_I);
      } else {  // ADD(S)
        opcode = (S ? A64Opcode::ADDS_I : A64Opcode::ADD_I);
      }

      if (S) {
        setDestinationRegisters(std::vector<Register>{genReg(Rd), nzcvReg()});
      } else {
        setDestinationRegisters(std::vector<Register>{genReg(Rd)});
      }

      setSourceRegisters(std::vector<Register>{filterZR(genReg(Rn))});

      metadata.sf = sf;
      metadata.imm = (shift ? (imm << 12) : imm);
      return;
    }
    case 0b100: {  // Logical (immediate)
      auto sf = bit(insn, 31);
      auto N = bit(insn, 22);
      if (!sf && N) {
        return unallocated();
      }

      auto Rd = (short)bits(insn, 0, 5);
      auto Rn = (short)bits(insn, 5, 5);
      auto imms = bits(insn, 10, 6);
      auto immr = bits(insn, 16, 6);

      setDestinationRegisters(std::vector<Register>{genReg(Rd)});
      setSourceRegisters(std::vector<Register>{filterZR(genReg(Rn))});

      metadata.sf = sf;
      metadata.N = N;
      metadata.imm = decodeBitMasks(N, imms, immr, true, (sf ? 64 : 32));

      auto opc = bits(insn, 29, 2);
      switch (opc) {
        case 0b01:
          opcode = A64Opcode::ORR_I;
          break;
        default:
          return nyi();
      }
      break;
    }
    default:
      return nyi();
  }
}
void A64Instruction::decodeA64BranchSystem(uint32_t insn) {
  uint8_t op0 = bits(insn, 29, 3);
  switch (op0) {
    case 0b010: {  // Conditional branch (immediate)
      isBranch_ = true;
      auto op1 = bit(insn, 25);
      auto o1 = bit(insn, 24);
      auto o0 = bit(insn, 4);
      if (op1 || o1 || o0) {
        return unallocated();
      }

      opcode = A64Opcode::B_cond;
      auto cond = bits(insn, 0, 4);
      auto offset = bits(insn, 5, 19);

      metadata.offset = signExtend(offset << 2, 21);
      metadata.cond = cond;

      setSourceRegisters({nzcvReg()});
      return;
    }
    case 0b000:
      [[fallthrough]];
    case 0b100: {  // Unconditional branch (immediate)
      isBranch_ = true;
      auto op = bit(insn, 31);
      int64_t imm = bits(insn, 0, 26);

      auto offset = signExtend(imm << 2, 28);

      if (op) {  // BL
        return nyi();
      }

      opcode = A64Opcode::B;
      metadata.offset = offset;
      return;
    }
    case 0b001:
      [[fallthrough]];
    case 0b101: {
      bool op1 = bit(insn, 25);
      if (op1) {  // Test and branch (immediate)
        isBranch_ = true;
        auto b5 = bit(insn, 31);
        auto op = bit(insn, 24);
        uint8_t b40 = bits(insn, 19, 5);
        int64_t imm = bits(insn, 5, 14);
        auto Rt = bits(insn, 0, 5);

        if (op) {  // TBNZ
          opcode = A64Opcode::TBNZ;
        } else {  // TBZ
          return nyi();
        }
        metadata.sf = b5;
        metadata.offset = signExtend(imm << 2, 16);
        metadata.bitPos = b5 ? (b40 << 1) : b40;

        setSourceRegisters({genReg(Rt)});

        return;
      } else {  // Compare and branch (immediate)
        return nyi();
      }
    }
    default:
      return nyi();
  }
  return nyi();
}
void A64Instruction::decodeA64LoadStore(uint32_t insn) {
  uint8_t op1 = bits(insn, 28, 2);
  switch (op1) {
    case 0b00: {
      // ASIMD structures & exclusives
      return nyi();
    }
    case 0b01: {
      // Literal
      return nyi();
    }
    case 0b10: {
      // Pair
      return nyi();
    }
    case 0b11: {
      // Single register
      auto op3_1 = bit(insn, 24);
      if (op3_1) {  // Load/store register (unsigned immediate)
        auto opc = bits(insn, 22, 2);
        auto Rt = (short)bits(insn, 0, 5);
        auto Rn = (short)bits(insn, 5, 5);
        auto imm = bits(insn, 10, 12);
        auto size = bits(insn, 30, 2);
        auto V = bit(insn, 26);

        if (V) {  // ASIMD
          return nyi();
        }

        switch (opc) {
          case 0b00: {  // STRx (immediate)
            isStore_ = true;
            switch (size) {
              case 0b00:
                return nyi();
              case 0b01:
                return nyi();
              default: {  // STR (immediate) - 32 & 64-bit variants
                opcode = A64Opcode::STR_I;
                metadata.wback = false;
                metadata.postindex = false;
                metadata.scale = size;
                metadata.offset = imm << size;

                setSourceRegisters({genReg(Rt), genReg(Rn)});

                return;
              }
            }
          }
          case 0b01: {  // LDRx (immediate)
            isLoad_ = true;
            switch (size) {
              case 0b00:
                return nyi();
              case 0b01:
                return nyi();
              default: {  // LDR (immediate) - 32 & 64 bit variants
                opcode = A64Opcode::LDR_I;
                metadata.wback = false;
                metadata.postindex = false;
                metadata.scale = size;
                metadata.offset = imm << size;

                setDestinationRegisters({genReg(Rt)});
                setSourceRegisters({genReg(Rn)});

                return;
              }
            }
          }
          default:
            return nyi();
        }
      }

      auto op5 = bits(insn, 10, 2);
      auto op4_5 = bit(insn, 21);
      if (op4_5) {
        switch (op5) {
          case 0b00: {  // Atomic memory operations
            return nyi();
          }
          case 0b10: {  // Load/store register (register offset)
            return nyi();
          }
          default: {  // Load/store register (pac)
            return nyi();
          }
        }
      }

      switch (op5) {
        case 0b00: {  // Load/store register (unscaled immediate)
          return nyi();
        }
        case 0b01: {  // Load/store register (immediate post-indexed)
          return nyi();
        }
        case 0b10: {  // Load/store register (unprivileged)
          return nyi();
        }
        case 0b11: {  // Load/store register (immediate pre-indexed)
          return nyi();
        }
      }

      return nyi();
    }
  }
  return nyi();
}
void A64Instruction::decodeA64DataRegister(uint32_t insn) {
  auto op1 = bit(insn, 28);

  bool op2_3 = bit(insn, 24);
  if (op1) {
    if (op2_3) {  // Data-processing (3 source)
      return nyi();
    } else {
      return nyi();
    }
  } else {
    if (op2_3) {
      bool op2_0 = bit(insn, 21);
      if (op2_0) {  // Add/subtract (extended register)
        return nyi();
      } else {  // Add/subtract (shifted register)
        bool op = bit(insn, 30);
        bool S = bit(insn, 29);

        bool sf = bit(insn, 31);
        auto Rd = bits(insn, 0, 5);
        auto Rn = bits(insn, 5, 5);
        auto imm = bits(insn, 10, 6);
        auto Rm = bits(insn, 16, 5);
        auto shift = bits(insn, 22, 2);

        if (shift != 0) {
          // TODO: Implement shift logic
          return nyi();
        }
        if (S) {
          return nyi();
        } else {
          if (op) {
            opcode = A64Opcode::SUB_Shift;
          } else {
            return nyi();
          }
        }
        metadata.sf = sf;
        metadata.imm = imm;

        setDestinationRegisters({genReg(Rd)});
        setSourceRegisters({filterZR(genReg(Rn)), filterZR(genReg(Rm))});
        return;
      }
    } else {  // Logical (shifted register)
      return nyi();
    }
  }
}
void A64Instruction::decodeA64DataFPSIMD(uint32_t insn) { nyi(); }

}  // namespace simeng
