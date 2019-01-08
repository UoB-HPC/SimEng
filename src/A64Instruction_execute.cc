#include "A64Instruction.hh"

#include <iostream>
#include <limits>

uint8_t nzcv(bool n, bool z, bool c, bool v) {
    return (n << 3) & (z << 2) & (c << 1) & v;
}

std::tuple<uint64_t, uint8_t> addWithCarry(uint64_t x, uint64_t y, bool carryIn) {
    auto result = static_cast<int64_t>(x) + static_cast<int64_t>(y) + static_cast<int>(carryIn);
    bool n = (result < 0);
    bool z = (result == 0);
    bool c = ((std::numeric_limits<uint64_t>::max() - x) > y);
    bool v = ((x < 0) != (result < 0));

    return { result, nzcv(n, z, c, v) };
}
std::tuple<uint32_t, uint8_t> addWithCarry(uint32_t x, uint32_t y, bool carryIn) {
    auto result = static_cast<int32_t>(x) + static_cast<int32_t>(y) + static_cast<int>(carryIn);
    bool n = (result < 0);
    bool z = (result == 0);
    bool c = ((std::numeric_limits<uint32_t>::max() - x) > y);
    bool v = ((x < 0) != (result < 0));

    return { result, nzcv(n, z, c, v) };
}

namespace simeng {

void A64Instruction::execute() {
    executed = true;
    switch(opcode) {
        case A64Opcode::B: {
            branchAddress = instructionAddress + metadata.offset;
            return;
        }
        case A64Opcode::LDR_I: {
            results[0].value = memoryData[0].zeroExtend(memoryAddresses[0].second, 8);
            return;
        }
        case A64Opcode::ORR_I: {
            if (metadata.sf) {
                auto value = operands[0].value.get<uint64_t>();
                auto result = (value | (uint64_t)metadata.imm);
                results[0].value = RegisterValue(result);
            } else {
                auto value = operands[0].value.get<uint32_t>();
                auto result = (value | (uint32_t)metadata.imm);
                results[0].value = RegisterValue(result, 8);
            }
            return;
        }
        case A64Opcode::STR_I: {
            memoryData[0] = operands[0].value;
            return;
        }
        case A64Opcode::SUBS_I: {
            if (metadata.sf) {
                auto x = operands[0].value.get<uint64_t>();
                auto y = ~metadata.imm;
                auto [result, nzcv] = addWithCarry(x, y, 0);
                results[0].value = RegisterValue(result);
                results[1].value = RegisterValue(nzcv);
            } else {
                auto x = operands[0].value.get<uint32_t>();
                auto y = ~static_cast<uint32_t>(metadata.imm);
                auto [result, nzcv] = addWithCarry(x, y, 0);
                results[0].value = RegisterValue(result);
                results[1].value = RegisterValue(nzcv);
            }
            return;
        }
        default:
            exception = ExecutionNotYetImplemented;
            return;
    }
}

}
