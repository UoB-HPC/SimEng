#include "A64Instruction.hh"
#include "RegisterFile.hh"

#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "A64Architecture.hh"
#include "AlwaysNotTakenPredictor.hh"
#include "Architecture.hh"
#include "BTBPredictor.hh"
#include "Core.hh"
#include "emulation/Core.hh"
#include "inorder/Core.hh"

enum class SimulationMode { Emulation, InOrderPipelined };

/** Tick the provided core model until it halts. */
int simulate(simeng::Core& core) {
  int iterations = 0;
  while (!core.hasHalted()) {
    // Tick the core until it detects the program has halted.
    core.tick();

    iterations++;
  }

  return iterations;
}

int main(int argc, char** argv) {
  SimulationMode mode = SimulationMode::InOrderPipelined;
  if (argc > 1 && !strcmp(argv[1], "emulation")) {
    mode = SimulationMode::Emulation;
  }

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
      // 0x321E03E0,  // orr w0, wzr, #4
      0x320C03E0,  // orr w0, wzr, #1048576
      // 0x321603E0, // orr w0, wzr, #1024
      0x71000400,  // subs w0, w0, #1
      // 0x320003E0, // orr w0, wzr, #1
      // 0x71000400, // subs w0, w0, #1
      0x54FFFFE1,  // b.ne -4
  };

  auto insnPtr = reinterpret_cast<char*>(hex);
  auto length = sizeof(hex);

  auto arch = simeng::A64Architecture();
  auto predictor = simeng::BTBPredictor(8);

  int iterations = 0;

  std::string modeString;
  std::unique_ptr<simeng::Core> core;
  switch (mode) {
    case SimulationMode::InOrderPipelined: {
      modeString = "In-Order Pipelined";
      core = std::make_unique<simeng::inorder::Core>(insnPtr, length, arch,
                                                     predictor);
      break;
    }
    default: {
      modeString = "Emulation";
      core = std::make_unique<simeng::emulation::Core>(insnPtr, length, arch);
      break;
    }
  };
  std::cout << "Running in " << modeString << " mode\n";
  std::cout << "Starting..." << std::endl;
  auto startTime = std::chrono::high_resolution_clock::now();

  iterations = simulate(*core);

  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  auto hz = iterations / (static_cast<double>(duration) / 1000.0);

  // Print stats
  auto stats = core->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
  }

  std::cout << "Finished " << iterations << " ticks in " << duration << "ms ("
            << hz << "Hz)" << std::endl;

  return 0;
}
