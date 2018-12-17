#include "A64Instruction.hh"
#include <iostream>

#define BITS(value, start, width) ((value >> start) & ((1 << width) - 1))
#define BIT(value, start) ((value >> start) & 1)
#define NOT(bits, length) (~bits & (1 << length - 1))
#define CONCAT(hi, lo, lowLen) ((hi << lowLen) & lo)
#define ONES(n) ((1 << (n)) - 1)
#define ROR(x, shift, size) ((x >> shift) | (x << (size - shift)))

/********************
 * HELPER FUNCTIONS
 *******************/

// Check for and mark WZR/XZR references
Register FilterZR(Register reg) {
    return (reg == 31 ? ZERO_REGISTER : reg);
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

            setDestinationRegisters(std::vector<Register> { Rd });
            setSourceRegisters(std::vector<Register> { FilterZR(Rn) });

            metadata.sf = sf;
            metadata.N = N;
            metadata.imm = decodeBitMasks(N, imms, immr, true, (sf ? 64 : 32));

            auto opc = BITS(insn, 29, 2);
            switch(opc) {
                case 0b01:
                    opcode = ORR_I;
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
    nyi();
}
void A64Instruction::decodeA64LoadStore(uint32_t insn) {
    nyi();
}
void A64Instruction::decodeA64DataRegister(uint32_t insn) {
    nyi();
}
void A64Instruction::decodeA64DataFPSIMD(uint32_t insn) {
    nyi();
}
