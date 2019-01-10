#include "A64Instruction.hh"
#include "registerFile.hh"

#include <cstring>
#include <iostream>

int main() {
  auto registerFile = simeng::RegisterFile({32, 32, 1});

  // uint32_t hex[] = {
  //     0x320003E0, // orr w0, wzr, #1
  //     0x321F0001, // orr w1, w0, #2
  //     0xB90003E1, // str w1, [sp]
  //     0xB94003E0, // ldr w0, [sp]
  //     0xF94003E0, // ldr x0, [sp]
  //     0x14000002, // b #8
  //     0x320003E0, // orr w0, wzr, #1
  //     0x32000002, // orr w2, w0, #1
  //     0x71000420, // subs w0, w1, #1
  // };

  // Simple loop; counts down from 1024*1024
  uint32_t hex[] = {
      0x320C03E0,  // orr w0, wzr, #1048576
      // 0x321603E0, // orr w0, wzr, #1024
      0x71000400,  // subs w0, w0, #1
      // 0x320003E0, // orr w0, wzr, #1
      // 0x71000400, // subs w0, w0, #1
      0x54FFFFE1,  // b.ne -4
  };

  uint64_t pc = 0;
  auto length = sizeof(hex);
  const auto pcIncrement = 4;

  unsigned char* memory = (unsigned char*)calloc(1024, 1);
  memory[4] = 1;

  std::cout << "Starting..." << std::endl;

  int iterations = 0;
  auto startTime = std::chrono::high_resolution_clock::now();

  while (pc >= 0 && pc < length) {
    iterations++;
    // Fetch
    auto macroop = simeng::A64Instruction::decode(&(hex[pc / pcIncrement]), pc);
    // std::cout << "0x" << pc << std::endl;

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
      for (auto const& request : addresses) {
        // std::cout << "Loading " << (int)request.second << " bytes from " <<
        // std::hex << request.first << std::endl;

        // Pointer manipulation to generate a RegisterValue from an arbitrary
        // memory address
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
        // std::cout << "Storing " << (int)request.second << " bytes to " <<
        // std::hex << request.first << std::endl;

        // Copy data to memory
        auto address = memory + request.first;
        memcpy(address, data[i].getAsVector<void>(), request.second);
      }
    } else if (uop->isBranch()) {
      pc = uop->getBranchAddress();
      // std::cout << "Branch: setting PC to " << std::hex << pc << std::endl;
    }

    // Writeback

    auto results = uop->getResults();
    // std::cout << "Results (" << std::hex << pc << "): ";
    auto destinations = uop->getDestinationRegisters();
    for (auto i = 0; i < results.size(); i++) {
      auto reg = destinations[i];
      registerFile.set(reg, results[i]);

      // std::cout << "r" << reg << " = " << std::hex <<
      // results[i].get<uint64_t>() << " ";
    }

    // std::cout << std::endl;
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  auto hz = iterations / (static_cast<double>(duration) / 1000.0);

  std::cout << "Finished " << iterations << " ticks in " << duration << "ms ("
            << hz << "Hz)" << std::endl;

  return 0;
}