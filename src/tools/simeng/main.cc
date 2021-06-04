#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "simeng/AlwaysNotTakenPredictor.hh"
#include "simeng/BTBPredictor.hh"
#include "simeng/BTB_BWTPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/VariableLatencyMemoryInterface.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "yaml-cpp/yaml.h"

enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

/** Tick the provided core model until it halts. */
int simulate(simeng::Core& core, simeng::MemoryInterface& instructionMemory,
             simeng::MemoryInterface& dataMemory) {
  int iterations = 0;
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
  SimulationMode mode = SimulationMode::InOrderPipelined;
  std::string executablePath = "";
  YAML::Node config;

  if (argc > 1) {
    config = simeng::ModelConfig(argv[1]).getConfigFile();

    if (config["Core"]["Simulation-Mode"].as<std::string>() == "emulation") {
      mode = SimulationMode::Emulation;
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "outoforder") {
      mode = SimulationMode::OutOfOrder;
    }
  } else {
    config = YAML::Load(DEFAULT_CONFIG);
  }

  if (argc > 2) {
    executablePath = std::string(argv[2]);
  }

  // Create the process image
  std::unique_ptr<simeng::kernel::LinuxProcess> process;

  if (executablePath.length() > 0) {
    // Attempt to create the process image from the specified command-line
    std::vector<std::string> commandLine(argv + 2, argv + argc);
    process = std::make_unique<simeng::kernel::LinuxProcess>(commandLine);
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

  // Create the architecture, with knowledge of the kernel
  auto arch = simeng::arch::aarch64::Architecture(kernel);

  auto predictor = simeng::BTBPredictor(
      config["Branch-Predictor"]["BTB-bitlength"].as<uint8_t>());

  auto config_ports = config["Ports"];
  std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>>
      portArrangement(config_ports.size());
  // Extract number of ports
  for (size_t i = 0; i < config_ports.size(); i++) {
    auto config_groups = config_ports[i]["Instruction-Support"];
    std::vector<std::vector<std::pair<uint16_t, uint8_t>>> groups(
        config_groups.size());
    // Extract number of groups in port
    for (size_t j = 0; j < config_groups.size(); j++) {
      auto config_group = config_groups[j];
      size_t num_compulsory = config_group["Compulsory"].size();
      size_t num_optional = config_group["Optional"].size();
      std::vector<std::pair<uint16_t, uint8_t>> group(num_compulsory +
                                                      num_optional);
      // Extract compulsory instructiuon group types in group
      for (size_t k = 0; k < num_compulsory; k++) {
        group[k] = {config_group["Compulsory"][k].as<uint8_t>(), 0};
      }
      // Extract optional instructiuon group types in group
      for (size_t k = num_compulsory; k < num_compulsory + num_optional; k++) {
        group[k] = {config_group["Optional"][k - num_compulsory].as<uint8_t>(),
                    1};
      }
      groups[j] = group;
    }
    portArrangement[i] = groups;
  }
  auto portAllocator = simeng::pipeline::BalancedPortAllocator(portArrangement);

  // Configure reservation station arrangment
  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement;
  for (size_t i = 0; i < config["Reservation-Stations"].size(); i++) {
    auto reservation_station = config["Reservation-Stations"][i];
    for (size_t j = 0; j < reservation_station["Ports"].size(); j++) {
      uint8_t port = reservation_station["Ports"][j].as<uint8_t>();
      if (rsArrangement.size() < port + 1) {
        rsArrangement.resize(port + 1);
      }
      rsArrangement[port] = {i, reservation_station["Size"].as<uint16_t>()};
    }
  }

  const uint16_t intDataMemoryLatency =
      config["L1-Cache"]["GeneralPurpose-Latency"].as<uint16_t>();
  const uint16_t fpDataMemoryLatency =
      config["L1-Cache"]["FloatingPoint-Latency"].as<uint16_t>();
  const uint16_t SVEDataMemoryLatency =
      config["L1-Cache"]["SVE-Latency"].as<uint16_t>();

  int iterations = 0;

  std::string modeString;
  std::unique_ptr<simeng::Core> core;
  std::unique_ptr<simeng::MemoryInterface> dataMemory;
  switch (mode) {
    case SimulationMode::OutOfOrder: {
      modeString = "Out-of-Order";
      dataMemory = std::make_unique<simeng::VariableLatencyMemoryInterface>(
          processMemory, processMemorySize, intDataMemoryLatency,
          fpDataMemoryLatency, SVEDataMemoryLatency);
      core = std::make_unique<simeng::models::outoforder::Core>(
          instructionMemory, *dataMemory, processMemorySize, entryPoint, arch,
          predictor, portAllocator, rsArrangement, config);
      break;
    }
    case SimulationMode::InOrderPipelined: {
      modeString = "In-Order Pipelined";
      std::unique_ptr<simeng::FlatMemoryInterface> flatDataMemory =
          std::make_unique<simeng::FlatMemoryInterface>(processMemory,
                                                        processMemorySize);
      core = std::make_unique<simeng::models::inorder::Core>(
          instructionMemory, *flatDataMemory, processMemorySize, entryPoint,
          arch, predictor);
      dataMemory = std::move(flatDataMemory);
      break;
    }
    default: {
      modeString = "Emulation";
      dataMemory = std::make_unique<simeng::FlatMemoryInterface>(
          processMemory, processMemorySize);
      core = std::make_unique<simeng::models::emulation::Core>(
          instructionMemory, *dataMemory, entryPoint, processMemorySize, arch);
      break;
    }
  };
  std::cout << "Running in " << modeString << " mode\n";
  std::cout << "Starting..." << std::endl;
  auto startTime = std::chrono::high_resolution_clock::now();

  iterations = simulate(*core, *dataMemory, instructionMemory);

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

  delete[] processMemory;

  return 0;
}