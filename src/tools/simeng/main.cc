#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>
#include <tuple>

#include "simeng/Config.hh"
#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/kernel/SimOS.hh"
#include "simeng/memory/SimpleMem.hh"
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
  std::cout << "[SimEng] Build metadata:" << std::endl;
  std::cout << "[SimEng] \tVersion: " SIMENG_VERSION << std::endl;
  std::cout << "[SimEng] \tCompile Time - Date: " __TIME__ " - " __DATE__
            << std::endl;
  std::cout << "[SimEng] \tBuild type: " SIMENG_BUILD_TYPE << std::endl;
  std::cout << "[SimEng] \tCompile options: " SIMENG_COMPILE_OPTIONS
            << std::endl;
  std::cout << "[SimEng] \tTest suite: " SIMENG_ENABLE_TESTS << std::endl;
  std::cout << std::endl;

  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(2684354560);  // 2.6 GiB

  // Create the instance of the OS
  simeng::kernel::SimOS simOS_kernel =
      simeng::kernel::SimOS(argc, argv, memory);

  // Get the SimEng runtime args
  auto [executablePath, executableArgs] = simOS_kernel.getParsedArgv();

  // Create the instance of the core to be simulated
  std::unique_ptr<simeng::CoreInstance> coreInstance =
      std::make_unique<simeng::CoreInstance>(executablePath, executableArgs,
                                             simOS_kernel.getSyscallHandler(),
                                             memory);

  // Get simulation objects needed to forward simulation
  std::shared_ptr<simeng::Core> core = coreInstance->getCore();
  std::shared_ptr<simeng::MemoryInterface> dataMemory =
      coreInstance->getDataMemory();
  std::shared_ptr<simeng::MemoryInterface> instructionMemory =
      coreInstance->getInstructionMemory();

  // Output general simulation details
  std::cout << "[SimEng] Running in " << coreInstance->getSimulationModeString()
            << " mode" << std::endl;
  std::cout << "[SimEng] Workload: " << executablePath;
  for (const auto& arg : executableArgs) std::cout << " " << arg;
  std::cout << std::endl;
  std::cout << "[SimEng] Config file: " << Config::getPath() << std::endl;

  // Run simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
  int iterations = 0;
  auto startTime = std::chrono::high_resolution_clock::now();
  iterations = simulate(*core, *dataMemory, *instructionMemory);

  // Get timing information
  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
          .count();
  double khz = (iterations / (static_cast<double>(duration) / 1000.0)) / 1000.0;
  uint64_t retired = core->getInstructionsRetiredCount();
  double mips = (retired / (static_cast<double>(duration))) / 1000.0;

  // Print stats
  std::cout << std::endl;
  auto stats = core->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << "[SimEng] " << key << ": " << value << std::endl;
  }
  std::cout << std::endl;
  std::cout << "[SimEng] Finished " << iterations << " ticks in " << duration
            << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
            << mips << " MIPS)" << std::endl;

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