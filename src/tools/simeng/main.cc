#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>
#include <tuple>

#include "simeng/Config.hh"
#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/version.hh"

/** Create a SimOS object depending on whether a binary file was specified. */
simeng::OS::SimOS simOsFactory(std::shared_ptr<simeng::memory::Mem> memory,
                               std::string executablePath,
                               std::vector<std::string> executableArgs) {
  if (executablePath == DEFAULT_STR) {
    // Use default program
    simeng::span<char> defaultPrg = simeng::span<char>(
        reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
    return simeng::OS::SimOS(memory, defaultPrg);
  }
  // Try to use binary specified in runtime args
  return simeng::OS::SimOS(memory, executablePath, executableArgs);
}

/** Tick the provided core model until it halts. */
int simulate(simeng::OS::SimOS& simOS, simeng::Core& core,
             simeng::memory::MMU& mmu) {
  uint64_t iterations = 0;

  // Tick the core and memory interfaces until the program has halted
  while (!simOS.hasHalted() || mmu.hasPendingRequests()) {
    // Tick SimOS
    simOS.tick();

    // Tick the core
    core.tick();

    // Tick memory
    mmu.tick();

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

  // Parse command line args
  std::string executablePath = DEFAULT_STR;
  std::vector<std::string> executableArgs;
  // Determine if a config file has been supplied.
  if (argc > 1) {
    // Set global config file to one at file path defined
    Config::set(std::string(argv[1]));

    // Determine if an executable has been supplied
    if (argc > 2) {
      executablePath = std::string(argv[2]);
      // Create a vector of any potential executable arguments from their
      // relative position within the argv variable
      char** startOfArgs = argv + 3;
      int numberofArgs = argc - 3;
      executableArgs =
          std::vector<std::string>(startOfArgs, startOfArgs + numberofArgs);
    }
  }

  // Get the memory size from the YAML config file.
  const size_t memorySize =
      Config::get()["Simulation-Memory"]["Size"].as<size_t>();

  // Create the simulation memory.
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(memorySize);

  // Create the instance of the lightweight Operating system
  simeng::OS::SimOS OS = simOsFactory(memory, executablePath, executableArgs);

  // Retrieve the virtual address translation function from SimOS and pass it to
  // the MMU. This function will be used to handle all virtual address
  // translations after a TLB miss.
  VAddrTranslator fn = OS.getVAddrTranslator();

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(
          Config::get()["LSQ-L1-Interface"]["Access-Latency"].as<uint16_t>(),
          fn);

  auto connection = std::make_shared<
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>();

  auto port1 = mmu->initPort();
  auto port2 = memory->initPort();

  connection->connect(port1, port2);

  // Create the instance of the core to be simulated
  std::unique_ptr<simeng::CoreInstance> coreInstance =
      std::make_unique<simeng::CoreInstance>(mmu, OS.getSyscallReceiver());

  // Get simulation objects needed to forward simulation
  std::shared_ptr<simeng::Core> core = coreInstance->getCore();

  // Register core with SimOS
  OS.registerCore(core);

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
  iterations = simulate(OS, *core, *mmu);

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
