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
#include "outoforder/Core.hh"

enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

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
  if (argc > 1) {
    if (!strcmp(argv[1], "emulation")) {
      mode = SimulationMode::Emulation;
    } else if ((!strcmp(argv[1], "outoforder"))) {
      mode = SimulationMode::OutOfOrder;
    }
  }

  char* memory = static_cast<char*>(calloc(1024, 1));

  // Simple program demonstrating various instructions
  // uint32_t hex[] = {
  //     0x320003E0,  // orr w0, wzr, #1
  //     0x321F0001,  // orr w1, w0, #2
  //     0xB90003E1,  // str w1, [sp]
  //     0xB94003E0,  // ldr w0, [sp]
  //     0xF94003E0,  // ldr x0, [sp]
  //     0x14000002,  // b #8
  //     0x320003E0,  // orr w0, wzr, #1
  //     0x32000002,  // orr w2, w0, #1
  //     0x71000420,  // subs w0, w1, #1
  // };

  // Simple loop; counts down from 1024*1024
  // uint32_t hex[] = {
  //     // 0x321E03E0,  // orr w0, wzr, #4
  //     0x320C03E0,  // orr w0, wzr, #1048576
  //     // 0x321603E0, // orr w0, wzr, #1024
  //     0x71000400,  // subs w0, w0, #1
  //     // 0x320003E0, // orr w0, wzr, #1
  //     // 0x71000400, // subs w0, w0, #1
  //     0x54FFFFE1,  // b.ne -4
  // };

  // Out-of-order test; counts down from 1024*1024, with an independent `orr` at
  // the start of each branch. With an instruction latency of 2 or greater, the
  // `orr` at the start of the next loop should issue/execute while the
  // preceding branch is waiting on the result from the `subs`.
  uint32_t hex[] = {
      // 0x321E03E0,  // orr w0, wzr, #4
      // 0x321603E0,  // orr w0, wzr, #1024
      0x320C03E0,  // orr w0, wzr, #1048576
      0x320003E1,  // orr w0, wzr, #1
      0x71000400,  // subs w0, w0, #1
      0x54FFFFC1,  // b.ne -8
  };

  // Load/store consistency test; a simple bubble sort algorithm
  // uint32_t hex[] = {
  //     0x320003E0,  //   orr w0, wzr, #1
  //     0x51000400,  //   sub w0, w0, #1

  //     0x11013001,  //   add w1, w0, #76
  //                  // .start:
  //     0x11000002,  //   add w2, w0, #0
  //                  // .compare:
  //     0xB9400044,  //   ldr w4, [x2, 0]
  //     0xB9400445,  //   ldr w5, [x2, 4]
  //     0x4B0400A6,  //   sub w6, w5, w4
  //     0x37F80046,  //   tbnz w6, #31, #8 (.swap)
  //     0x14000003,  //   b #12 (.next)
  //                  // .swap:
  //     0xB9000444,  //   str w4, [x2, 4]
  //     0xB9000045,  //   str w5, [x2, 0]
  //                  // .next:
  //     0x11001042,  //   add w2, w2, #4
  //     0x4B010046,  //   sub w6, w2, w1
  //     0x37FFFEE6,  //   tbnz w6, #31, #-36 (.compare)
  //     0x51001021,  //   sub w1, w1, #4
  //     0x4B010006,  //   sub w6, w0, w1
  //     0x37FFFE66,  //   tbnz w6, #31, #-52 (.start)
  // };

  // // Some arbitrary values to sort
  // std::vector<int> memoryValues = {9,  6, 7, 20, 5,   0,  80, 2,  1,  6,
  //                                  17, 4, 3, 22, 117, 11, 4,  12, 10, 18};
  // memcpy(memory, memoryValues.data(), memoryValues.size() * sizeof(int));

  auto insnPtr = reinterpret_cast<char*>(hex);
  auto length = sizeof(hex);

  auto arch = simeng::A64Architecture();
  auto predictor = simeng::BTBPredictor(8);

  int iterations = 0;

  std::string modeString;
  std::unique_ptr<simeng::Core> core;
  switch (mode) {
    case SimulationMode::OutOfOrder: {
      modeString = "Out-of-Order";
      core = std::make_unique<simeng::outoforder::Core>(insnPtr, length, arch,
                                                        predictor, memory);
      break;
    }
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
  std::cout << "\n";
  auto stats = core->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
  }

  std::cout << "\nFinished " << iterations << " ticks in " << duration << "ms ("
            << hz << "Hz)" << std::endl;

  return 0;
}
