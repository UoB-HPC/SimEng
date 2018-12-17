#include "A64Instruction.hh"

#include <iostream>

void A64Instruction::execute() {
    executed = true;
    switch(opcode) {
        case ORR_I: {
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
        default:
            exception = ExecutionNotYetImplemented;
            return;
    }
}
