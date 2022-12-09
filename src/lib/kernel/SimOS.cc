#include "simeng/kernel/SimOS.hh"

namespace simeng {

namespace kernel {

SimOS::SimOS(const std::vector<std::string>& commandLine, YAML::Node config) {
  // Define vector of all currently supported special file paths & files.
  supportedSpecialFiles_.insert(
      supportedSpecialFiles_.end(),
      {"/proc/cpuinfo", "proc/stat", "/sys/devices/system/cpu",
       "/sys/devices/system/cpu/online", "core_id", "physical_package_id"});

  // Create the initial Process defined by the command line, or default if no
  // executable is given.
}

void createCores(const uint64_t numCores) {
  // TODO: Support multi-core
  if (numCores != 1) {
    std::cerr << "[SimEng:SimOS] Invalid number of Cores \"" << numCores
              << "\". Please configure for single core simulation."
              << std::endl;
    exit(1);
  }
}

// In place of Simulate in Main - drives whole simulation.
double execute() { return 0.0; }

}  // namespace kernel
}  // namespace simeng