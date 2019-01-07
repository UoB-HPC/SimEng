#include "A64Instruction.hh"
#include <iostream>

#define BITS(value, start, width) ((value >> start) & ((1 << width) - 1))
#define BIT(value, start) ((value >> start) & 1)
#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

namespace simeng {

/********************
 * HELPER FUNCTIONS
 *******************/

constexpr Register GenReg(uint16_t tag) {
    return { A64RegisterType::GENERAL, tag };
}

// Check for and mark WZR/XZR references
Register FilterZR(Register reg) {
    return (reg.type == A64RegisterType::GENERAL && reg.tag == 31
        ? A64Instruction::ZERO_REGISTER : reg);
}

uint64_t decodeBitMasks(uint8_t immN, uint8_t imms, uint8_t immr, bool immediate, int size) {
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

void A64Instruction::decodeA64(uint32_t insn) {
    auto op0 = (insn >> 25) & 0b1111;
    auto op0_1 = (op0 >> 1) & 1;
    auto op0_2 = (op0 >> 2) & 1;

    if (op0_2) {
        auto op0_0 = op0 & 1;
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

    auto op0_3 = (op0 >> 3) & 1;
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
    exception = EncodingNotYetImplemented;
}
void A64Instruction::unallocated() {
    exception = EncodingUnallocated;
}

void A64Instruction::decodeA64DataImmediate(uint32_t insn) {
    auto op0 = BITS(insn, 23, 3);
    switch(op0) {
        case 0b100: { // Logical (immediate)
            auto sf = BIT(insn, 31);
            auto N = BIT(insn, 22);
            if (!sf && N) {
                return unallocated();
            }

            auto Rd = (short)BITS(insn, 0, 5);
            auto Rn = (short)BITS(insn, 5, 5);
            auto imms = BITS(insn, 10, 6);
            auto immr = BITS(insn, 16, 6);

            setDestinationRegisters(std::vector<Register> { GenReg(Rd) });
            setSourceRegisters(std::vector<Register> { FilterZR(GenReg(Rn)) });

            metadata.sf = sf;
            metadata.N = N;
            metadata.imm = decodeBitMasks(N, imms, immr, true, (sf ? 64 : 32));

            auto opc = BITS(insn, 29, 2);
            switch(opc) {
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
    auto op0 = BITS(insn, 29, 3);
    switch(op0) {
        case 0b000:
        case 0b100: { // Unconditional branch (immediate)
            isBranch_ = true;
            auto op = BIT(insn, 31);
            int64_t imm = BITS(insn, 0, 25);
            auto negative = BIT(insn, 25);

            auto offset = (imm << 2) * (negative ? -1 : 1);

            if (op) { // BL
                return nyi();
            }

            opcode = A64Opcode::B;
            metadata.offset = offset;
        }
        default: {
            return nyi();
        }
    }
    return nyi();
}
void A64Instruction::decodeA64LoadStore(uint32_t insn) {
    auto op1 = BITS(insn, 28, 2);
    switch(op1) {
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
            auto op3_1 = BIT(insn, 24);
            if (op3_1) { // Load/store register (unsigned immediate)
                auto opc = BITS(insn, 22, 2);
                auto Rt = (short)BITS(insn, 0, 5);
                auto Rn = (short)BITS(insn, 5, 5);
                auto imm = BITS(insn, 10, 12);
                auto size = BITS(insn, 30, 2);
                auto V = BIT(insn, 26);

                if (V) { // ASIMD
                    return nyi();
                }
                
                switch(opc) {
                    case 0b00: { // STRx (immediate)
                        isStore_ = true;
                        switch(size) {
                            case 0b00: return nyi();
                            case 0b01: return nyi();
                            default: { // STR (immediate) - 32 & 64-bit variants
                                opcode = A64Opcode::STR_I;
                                metadata.wback = false;
                                metadata.postindex = false;
                                metadata.scale = size;
                                metadata.offset = imm << size;

                                setSourceRegisters(std::vector<Register> { GenReg(Rt), GenReg(Rn) });

                                return;
                            }
                        }
                    }
                    case 0b01: { // LDRx (immediate)
                        isLoad_ = true;
                        switch(size) {
                            case 0b00: return nyi();
                            case 0b01: return nyi();
                            default: { // LDR (immediate) - 32 & 64 bit variants
                                opcode = A64Opcode::LDR_I;
                                metadata.wback = false;
                                metadata.postindex = false;
                                metadata.scale = size;
                                metadata.offset = imm << size;

                                setDestinationRegisters(std::vector<Register> { GenReg(Rt) });
                                setSourceRegisters(std::vector<Register> { GenReg(Rn) });

                                return;
                            }
                        }
                    }
                    default:
                        return nyi();
                }
            }

            auto op5 = BITS(insn, 10, 2);
            auto op4_5 = BIT(insn, 21);
            if (op4_5) {
                switch(op5) {
                    case 0b00: { // Atomic memory operations
                        return nyi();
                    }
                    case 0b10: { // Load/store register (register offset)
                        return nyi();
                    }
                    default: { // Load/store register (pac)
                        return nyi();
                    }
                }
            }

            switch(op5) {
                case 0b00: { // Load/store register (unscaled immediate)
                    return nyi();
                }
                case 0b01: { // Load/store register (immediate post-indexed)
                    return nyi();
                }
                case 0b10: { // Load/store register (unprivileged)
                    return nyi();
                }
                case 0b11: { // Load/store register (immediate pre-indexed)
                    return nyi();
                }
            }

            return nyi();
        }
    }
    return nyi();
}
void A64Instruction::decodeA64DataRegister(uint32_t insn) {
    nyi();
}
void A64Instruction::decodeA64DataFPSIMD(uint32_t insn) {
    nyi();
}

}
