#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>

#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/version.hh"

/** Tick the provided core model until it halts. */
int simulate(simeng::Core& core, simeng::MemoryInterface& dataMemory,
             simeng::MemoryInterface& instructionMemory,
             std::ofstream* traceOut, std::ofstream* probeOut) {
  uint64_t iterations = 0;

  int probeIndex = 1;
  uint64_t probeCycle = 1;
  int start = 1;
  std::string traceWriteOut = "";
  std::string probeWriteOut = "";
  // Tick the core and memory interfaces until the program has halted
  while (!core.hasHalted() || dataMemory.hasPendingRequests()) {
    // Tick the core
    core.tick();

    // Tick memory
    instructionMemory.tick();
    dataMemory.tick();

    // Write out trace data
    std::map<uint64_t, simeng::Trace*>::iterator itM = traceMap.begin();
    // loop through tracing map and write out the finished instructions
    while (itM != traceMap.end()) {
      char str[1000] = "";
      int success = itM->second->writeCycleOut(str, itM->first, "outoforder");
      // If written out remove instruction from map
      if (success) {
        delete itM->second;
        itM = traceMap.erase(itM);
        traceWriteOut += str;
        if (traceWriteOut.length() > 8196) {
          *traceOut << traceWriteOut;
          traceWriteOut = "";
        }
      } else
        break;
    }
    // Write out probe data
    std::list<simeng::Trace*>::iterator itL = probeList.begin();
    int newline = 0;
    while (itL != probeList.end()) {
      simeng::probeTrace pt = (*itL)->getProbeTraces();
      if (pt.cycle == probeCycle)
        newline = 0;
      else {
        newline = 1;
        for (uint64_t i = 0; i < (pt.cycle - probeCycle - 1); i++) {
          probeWriteOut += "\n-";
        }
        probeCycle = pt.cycle;
      }
      char str[4] = "";
      int success = (*itL)->writeProbeOut(str, probeIndex, newline, start);
      // Increment probe counter
      probeIndex++;
      // If written out remove probe from list
      if (success) {
        start = 0;
        delete (*itL);
        itL = probeList.erase(itL);
        probeWriteOut += str;
        if (probeWriteOut.length() > 8196) {
          *probeOut << probeWriteOut;
          probeWriteOut = "";
        }
      } else
        itL++;
    }
    iterations++;
    trace_cycle = iterations;
  }
  if (traceWriteOut != "") {
    *traceOut << traceWriteOut;
  }
  if (probeWriteOut != "") {
    *probeOut << probeWriteOut;
  }
  // *probeOut << "\n";
  /*// iterator for in(I) map(M)
  std::map<uint64_t, simeng::Trace*>::iterator itIM;
  for(itIM = traceMap->begin(); itIM != traceMap->end(); itIM++){
    simeng::cycleTrace tr = itIM->second->getCycleTraces();
    printf("ID: %" PRId64 ", fetch: %" PRId64 ", \tinstruction: %s,\t decode: %"
  PRId64 ", dispatch: %" PRId64 ", issue: %" PRId64 ", complete: %" PRId64 ",
  retire: %" PRId64 ", finished: %d\n", itIM->first, tr.fetch.cycle,
  tr.fetch.disasm.c_str(), tr.decode, tr.dispatch, tr.issue, tr.complete,
  tr.retire, tr.finished);
  }*/

  return iterations;
}

bool tracing;
bool enableTrace;
bool probing;
bool enableProbe;
bool enableFocus;
bool recordEvents;
uint64_t trace_cycle;
uint64_t traceId;
std::map<uint64_t, simeng::Trace*> traceMap;
std::list<simeng::Trace*> probeList;

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

  // Create the instance of the core to be simulated
  std::unique_ptr<simeng::CoreInstance> coreInstance;
  std::string executablePath = "";
  std::string configFilePath = "";
  std::vector<std::string> executableArgs = {};

  // Determine if a config file has been supplied.
  // Set defaults to tracing variables
  tracing = false;
  enableTrace = false;
  probing = false;
  enableProbe = false;
  enableFocus = false;
  recordEvents = true;
  trace_cycle = 1;
  traceId = 1;

  if (argc > 1) {
    configFilePath = std::string(argv[1]);
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
    coreInstance = std::make_unique<simeng::CoreInstance>(
        configFilePath, executablePath, executableArgs);
  } else {
    // Without a config file, no executable can be supplied so pass default
    // (empty) values for executable information
    coreInstance =
        std::make_unique<simeng::CoreInstance>(executablePath, executableArgs);
    configFilePath = "Default";
  }

  // Replace empty executablePath string with more useful content for
  // outputting
  if (executablePath == "") executablePath = "Default";

  // Initialise trace/probe objects
  std::ofstream traceOut;
  traceOut.open("trace.out", std::ofstream::binary | std::ofstream::trunc);
  std::ofstream probeOut;
  probeOut.open("probe.out", std::ofstream::binary | std::ofstream::trunc);

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
  std::cout << "[SimEng] Config file: " << configFilePath << std::endl;
  std::cout << "Tracing enabled\n";
  std::cout << "Probing enabled\n";

  // Run simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
  int iterations = 0;
  auto startTime = std::chrono::high_resolution_clock::now();
  iterations =
      simulate(*core, *dataMemory, *instructionMemory, &traceOut, &probeOut);

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

  traceOut.close();
  probeOut.close();
  return 0;
}