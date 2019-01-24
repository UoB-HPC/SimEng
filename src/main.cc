#include "A64Instruction.hh"
#include "RegisterFile.hh"

#include <chrono>
#include <cstring>
#include <iostream>

#include "A64Architecture.hh"
#include "Core.hh"

int main() {
  // Create an ISA description
  std::unique_ptr<simeng::Architecture> isa =
      std::make_unique<simeng::A64Architecture>();

  auto registerFile = simeng::RegisterFile({32, 32, 1});

  // Simple program demonstrating various instructions
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

  unsigned char* memory = (unsigned char*)calloc(1024, 1);
  memory[4] = 1;

  std::cout << "Starting..." << std::endl;

  int iterations = 0;
  auto startTime = std::chrono::high_resolution_clock::now();

  auto insnPtr = reinterpret_cast<char*>(hex) + pc;

  auto arch = simeng::A64Architecture();
  auto core = simeng::Core(insnPtr, length, arch);

  while (!core.hasHalted()) {

    core.tick();
    
    iterations++;
  }

  // while (pc >= 0 && pc < length) {
  //   iterations++;


  //   // Fetch
  //   auto insnPtr = reinterpret_cast<char*>(hex) + pc;
  //   auto [macroop, bytesRead] = isa->predecode(insnPtr, 4, pc);

  //   pc += bytesRead;

  //   // Decode
  //   auto uop = macroop[0];

  //   // Issue
  //   auto registers = uop->getOperandRegisters();
  //   for (size_t i = 0; i < registers.size(); i++) {
  //     auto reg = registers[i];
  //     if (!uop->isOperandReady(i)) {
  //       uop->supplyOperand(reg, registerFile.get(reg));
  //     }
  //   }

  //   // Execute
  //   if (uop->isLoad()) {
  //     auto addresses = uop->generateAddresses();
  //     for (auto const& request : addresses) {
  //       // Pointer manipulation to generate a RegisterValue from an arbitrary
  //       // memory address
  //       auto buffer = malloc(request.second);
  //       memcpy(buffer, memory + request.first, request.second);

  //       auto ptr = std::shared_ptr<uint8_t>((uint8_t*)buffer, free);
  //       auto data = simeng::RegisterValue(ptr);

  //       uop->supplyData(request.first, data);
  //     }
  //   } else if (uop->isStore()) {
  //     uop->generateAddresses();
  //   }
  //   uop->execute();

  //   if (uop->isStore()) {
  //     auto addresses = uop->getGeneratedAddresses();
  //     auto data = uop->getData();
  //     for (size_t i = 0; i < addresses.size(); i++) {
  //       auto request = addresses[i];

  //       // Copy data to memory
  //       auto address = memory + request.first;
  //       memcpy(address, data[i].getAsVector<void>(), request.second);
  //     }
  //   } else if (uop->isBranch()) {
  //     pc = uop->getBranchAddress();
  //   }

  //   // Writeback

  //   auto results = uop->getResults();
  //   auto destinations = uop->getDestinationRegisters();
  //   for (size_t i = 0; i < results.size(); i++) {
  //     auto reg = destinations[i];
  //     registerFile.set(reg, results[i]);
  //   }
  // }

  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  auto hz = iterations / (static_cast<double>(duration) / 1000.0);

  std::cout << "Finished " << iterations << " ticks in " << duration << "ms ("
            << hz << "Hz)" << std::endl;

  return 0;
}
