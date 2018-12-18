#include "registerFile.hh"
#include "A64Instruction.hh"

#include <iostream>

int main() {
    auto registerFile = simeng::RegisterFile(32);

    uint32_t hex[] = {
        0x320003E0, // orr w0, wzr, #1
        0x321F0001, // orr w1, w0, #2
    };

    auto pc = 0;
    auto length = sizeof(hex);
    const auto pcIncrement = 4;

    while (pc >= 0 && pc < length) {
        // Fetch
        auto macroop = simeng::A64Instruction::decode(&(hex[pc/pcIncrement]));

        pc += pcIncrement;

        // Decode
        auto uop = macroop[0];

        // Issue
        auto registers = uop->getOperandRegisters();
        for (auto i = 0; i < registers.size(); i++) {
            auto reg = registers[i];
            if (!uop->isOperandReady(i)) {
                uop->supplyOperand(reg, registerFile.get(reg));
            }
        }

        // Execute
        uop->execute();

        // Writeback
        auto results = uop->getResults();
        auto destinations = uop->getDestinationRegisters();
        std::cout << "Results: ";
        for (auto i = 0; i < results.size(); i++) {
            auto reg = destinations[i];
            registerFile.set(reg, results[i]);

            std::cout << "r" << reg << " = " << std::hex << results[i].get<uint64_t>() << " ";
        }
        std::cout << std::endl;
    }

    return 0;
}