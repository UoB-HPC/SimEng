#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "AlwaysNotTakenPredictor.hh"
#include "BTBPredictor.hh"
#include "Core.hh"
#include "Elf.hh"
#include "FlatMemoryInterface.hh"
#include "arch/Architecture.hh"
#include "arch/aarch64/Architecture.hh"
#include "arch/aarch64/Instruction.hh"
#include "kernel/Linux.hh"
#include "models/emulation/Core.hh"
#include "models/inorder/Core.hh"
#include "models/outoforder/Core.hh"
#include "pipeline/BalancedPortAllocator.hh"

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
  std::string executablePath = "";

  if (argc > 1) {
    if (!strcmp(argv[1], "emulation")) {
      mode = SimulationMode::Emulation;
    } else if ((!strcmp(argv[1], "outoforder"))) {
      mode = SimulationMode::OutOfOrder;
    }

    if (argc > 2) {
      executablePath = std::string(argv[2]);
    }
  }

  // Create the process image
  std::unique_ptr<simeng::kernel::LinuxProcess> process;

  if (executablePath.length() > 0) {
    // Attempt to create the process image from the specified file
    process = std::make_unique<simeng::kernel::LinuxProcess>(argv[2]);
    if (!process->isValid()) {
      std::cerr << "Could not read/parse " << argv[2] << std::endl;
      exit(1);
    }
  } else {
    // Create the process image directly

    // char* memory = new char[1024]();

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

    // Out-of-order test; counts down from 1024*1024, with an independent `orr`
    // at the start of each branch. With an instruction latency of 2 or greater,
    // the `orr` at the start of the next loop should issue/execute while the
    // preceding branch is waiting on the result from the `subs`.
    uint32_t hex[] = {
        // 0x321E03E0,  // orr w0, wzr, #4
        // 0x321603E0,  // orr w0, wzr, #1024
        0x320C03E0,  // orr w0, wzr, #1048576
        0x320003E1,  // orr w0, wzr, #1
        0x71000400,  // subs w0, w0, #1
        // 0x00000000,  // invalid
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

    // Force a load/store ordering violation
    // uint32_t hex[] = {
    //     0x320003E0,  //   orr w0, wzr, #1
    //     0x51000400,  //   sub w0, w0, #1

    //     0x11000002,  //   add w2, w0, #0
    //     0x11013001,  //   add w1, w0, #76

    //     0xB9000041,  //   str w1, [x2]
    //     0xB9400043,  //   ldr w3, [x2]
    //     0xB9000443,  //   str w3, [x2, 4]
    // };

    // Some arbitrary values to sort
    // std::vector<int> memoryValues = {9,  6, 7, 20, 5,   0,  80, 2,  1,  6,
    //                                  17, 4, 3, 22, 117, 11, 4,  12, 10, 18};
    // memcpy(memory, memoryValues.data(), memoryValues.size() * sizeof(int));

    process = std::make_unique<simeng::kernel::LinuxProcess>(
        simeng::span<char>(reinterpret_cast<char*>(hex), sizeof(hex)));
  }

  // Read the process image and copy to memory
  auto processImage = process->getProcessImage();
  size_t processMemorySize = processImage.size();
  char* processMemory = new char[processMemorySize]();
  std::copy(processImage.begin(), processImage.end(), processMemory);

  uint64_t entryPoint = process->getEntryPoint();

  // Create the OS kernel with the process
  simeng::kernel::Linux kernel;
  kernel.createProcess(*process.get());

  simeng::FlatMemoryInterface instructionMemory(processMemory,
                                                processMemorySize);
  simeng::FlatMemoryInterface dataMemory(processMemory, processMemorySize);

  // Create the architecture, with knowledge of the kernel
  auto arch = simeng::arch::aarch64::Architecture(kernel);

  auto predictor = simeng::BTBPredictor(8);

  // TODO: Construct port arrangement from config options
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {simeng::arch::aarch64::InstructionGroups::LOAD,
       simeng::arch::aarch64::InstructionGroups::STORE},
      {simeng::arch::aarch64::InstructionGroups::ARITHMETIC},
      {simeng::arch::aarch64::InstructionGroups::ARITHMETIC,
       simeng::arch::aarch64::InstructionGroups::BRANCH}};
  auto portAllocator = simeng::pipeline::BalancedPortAllocator(portArrangement);

  int iterations = 0;

  std::string modeString;
  std::unique_ptr<simeng::Core> core;
  switch (mode) {
    case SimulationMode::OutOfOrder: {
      modeString = "Out-of-Order";
      core = std::make_unique<simeng::models::outoforder::Core>(
          instructionMemory, dataMemory, processMemorySize, entryPoint, arch,
          predictor, portAllocator);
      break;
    }
    case SimulationMode::InOrderPipelined: {
      modeString = "In-Order Pipelined";
      core = std::make_unique<simeng::models::inorder::Core>(
          instructionMemory, dataMemory, processMemorySize, entryPoint, arch,
          predictor);
      break;
    }
    default: {
      modeString = "Emulation";
      core = std::make_unique<simeng::models::emulation::Core>(
          instructionMemory, dataMemory, entryPoint, processMemorySize, arch);
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

  delete[] processMemory;

  return 0;
}
