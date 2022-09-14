#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/version.hh"

/** Tick the provided core model until it halts. */
int simulate(simeng::Core& core, simeng::MemoryInterface& dataMemory,
             simeng::MemoryInterface& instructionMemory) {
  uint64_t iterations = 0;

  // Tick the core and memory interfaces until the program has halted
  while (!core.hasHalted() || dataMemory.hasPendingRequests()) {
    // Tick the core
    core.tick();

    // Tick memory
    instructionMemory.tick();
    dataMemory.tick();

    iterations++;
  }

  return iterations;
}

int main(int argc, char** argv) {
  // Print out build metadata
  std::cout << "Build metadata:" << std::endl;
  std::cout << "\tVersion: " SIMENG_VERSION << std::endl;
  std::cout << "\tCompile Time - Date: " __TIME__ " - " __DATE__ << std::endl;
  std::cout << "\tBuild type: " SIMENG_BUILD_TYPE << std::endl;
  std::cout << "\tCompile options: " SIMENG_COMPILE_OPTIONS << std::endl;
  std::cout << "\tTest suite: " SIMENG_ENABLE_TESTS << std::endl;
  std::cout << std::endl;

  // Create the instance of the core to be simulated
  std::unique_ptr<simeng::CoreInstance> coreInstance;
  if (argc > 1) {
    coreInstance = std::make_unique<simeng::CoreInstance>(argv[1]);
  } else {
    coreInstance = std::make_unique<simeng::CoreInstance>();
  }

  // Extract path of binary to be run if available
  std::string executablePath = "";
  if (argc > 2) {
    executablePath = std::string(argv[2]);
  }

  if (executablePath.length() > 0) {
    // Attempt to create the process image from the specified command-line
    std::vector<std::string> commandLine(argv + 2, argv + argc);
    coreInstance->createProcess(commandLine);
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
                     // .exit:
        0xD2800000,  // mov x0, #0
        0xD2800BC8,  // mov x8, #94
        0xD4000001,  // svc #0
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

    coreInstance->createProcess(
        simeng::span<char>(reinterpret_cast<char*>(hex), sizeof(hex)));
  }

  // Get simualtion mode and data memory interface type
  simeng::SimulationMode mode = coreInstance->getSimulationMode();
  simeng::MemInterfaceType L1Dtype = simeng::MemInterfaceType::Flat;
  std::string modeString = "Emulation";
  if (mode == simeng::SimulationMode::OutOfOrder) {
    modeString = "Out-of-Order";
    L1Dtype = simeng::MemInterfaceType::Fixed;
  } else if (mode == simeng::SimulationMode::InOrderPipelined) {
    modeString = "In-Order Pipelined";
  }

  // Create memory interfaces
  std::shared_ptr<simeng::MemoryInterface> dataMemory =
      coreInstance->createL1DataMemory(L1Dtype);
  std::shared_ptr<simeng::MemoryInterface> instructionMemory =
      coreInstance->createL1InstructionMemory(simeng::MemInterfaceType::Flat);

  // Create core
  std::shared_ptr<simeng::Core> core = coreInstance->createCore();

  // Create Special Files directory if indicated to do so in Config
  coreInstance->createSpecialFileDirectory();

  // Run simulation
  std::cout << "Running in " << modeString << " mode\n";
  std::cout << "Starting..." << std::endl;
  auto startTime = std::chrono::high_resolution_clock::now();
  int iterations = 0;
  iterations = simulate(*core, *dataMemory, *instructionMemory);

  // Get timing information
  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  auto hz = iterations / (static_cast<double>(duration) / 1000.0);
  auto khz = hz / 1000.0;
  auto retired = core->getInstructionsRetiredCount();
  auto mips = retired / static_cast<double>(duration) / 1000.0;

  // Print stats
  std::cout << "\n";
  auto stats = core->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
  }

  std::cout << "\nFinished " << iterations << " ticks in " << duration << "ms ("
            << std::round(khz) << " kHz, " << std::setprecision(2) << mips
            << " MIPS)" << std::endl;

  // If Special Files directory was created, now remove it
  // if (config["CPU-Info"]["Generate-Special-Dir"].as<std::string>() == "T") {
  // Remove special files dir
  // SFdir.RemoveExistingSFDir();
  //}

// Print build metadata and core statistics in YAML format
// to facilitate parsing. Print "YAML-SEQ" to indicate beginning
// of YAML formatted data.
#ifdef YAML_OUTPUT

  YAML::Emitter out;
  out << YAML::BeginDoc << YAML::BeginMap;
  out << YAML::Key << "build metadata" << YAML::Value;
  out << YAML::BeginSeq;
  out << "Version: " SIMENG_VERSION;
  out << "Compile Time - Date: " __TIME__ " - " __DATE__;
  out << "Build type: " SIMENG_BUILD_TYPE;
  out << "Compile options: " SIMENG_COMPILE_OPTIONS;
  out << "Test suite: " SIMENG_ENABLE_TESTS;
  out << YAML::EndSeq;
  for (const auto& [key, value] : stats) {
    out << YAML::Key << key << YAML::Value << value;
  }
  out << YAML::Key << "duration" << YAML::Value << duration;
  out << YAML::Key << "mips" << YAML::Value << mips;
  out << YAML::Key << "cycles_per_sec" << YAML::Value
      << std::stod(stats["cycles"]) / (duration / 1000.0);
  out << YAML::EndMap << YAML::EndDoc;

  std::cout << "YAML-SEQ\n";
  std::cout << out.c_str() << std::endl;

#endif

  return 0;
}