#include "registerFile.hh"
#include "A64Instruction.hh"

#include <cstring>
#include <iostream>

int main() {
    auto registerFile = simeng::RegisterFile(32);

    uint32_t hex[] = {
        0x320003E0, // orr w0, wzr, #1
        0x321F0001, // orr w1, w0, #2
        0xB90003E1, // str w1, [sp]
        0xB94003E0, // ldr w0, [sp]
        0xF94003E0, // ldr x0, [sp]
    };

    auto pc = 0;
    auto length = sizeof(hex);
    const auto pcIncrement = 4;

    unsigned char* memory = (unsigned char*)calloc(1024, 1);
    memory[4] = 1;

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
        if (uop->isLoad()) {
            auto addresses = uop->generateAddresses();
            for (auto const &request : addresses) {
                std::cout << "Loading " << (int)request.second << " bytes from " << std::hex << request.first << std::endl;
                
                // Pointer manipulation to generate a RegisterValue from an arbitrary memory address
                auto buffer = malloc(request.second);
                memcpy(buffer, memory + request.first, request.second);

                auto ptr = std::shared_ptr<uint8_t>((uint8_t*)buffer, free);
                auto data = simeng::RegisterValue(ptr);

                uop->supplyData(request.first, data);
            }
        } else if (uop->isStore()) {
            uop->generateAddresses();
        }
        uop->execute();

        if (uop->isStore()) {
            auto addresses = uop->getGeneratedAddresses();
            auto data = uop->getData();
            for (int i = 0; i < addresses.size(); i++) {
                auto request = addresses[i];
                std::cout << "Storing " << (int)request.second << " bytes to " << std::hex << request.first << std::endl;

                // Copy data to memory
                auto address = memory + request.first;
                memcpy(address, data[i].getAsVector<void>(), request.second);
            }
        }

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