#include "A64Instruction.hh"

#include <iostream>

namespace simeng {

std::vector<std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
    if (!isLoad() && !isStore()) {
        // Not a load or store
        return {};
    }

    switch(opcode) {
        case LDR_I: {
            if (metadata.wback) {
                exception = ExecutionNotYetImplemented;
                return {};
            }

            auto address = operands[0].value.get<uint64_t>() + metadata.offset;
            setMemoryAddresses({ { address, 1 << metadata.scale } });
            return memoryAddresses;
        }
        default:
            return {};
    }
}

}
