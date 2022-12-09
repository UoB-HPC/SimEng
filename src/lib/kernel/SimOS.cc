#include "simeng/kernel/SimOS.hh"

namespace simeng {
namespace kernel {

SimOS::SimOS(
    /*const std::vector<std::string>& commandLine, YAML::Node config*/)
    : syscalls_(SyscallHandler(processStates_)) {
  // Create the initial Process defined by the command line, or default if no
  // executable is given.

  // Create SyscallHandler Object
}

void SimOS::createCores(const uint64_t numCores) {
  // TODO: Support multi-core
  if (numCores != 1) {
    std::cerr << "[SimEng:SimOS] Invalid number of Cores \"" << numCores
              << "\". Please configure for single core simulation."
              << std::endl;
    exit(1);
  }
}

// In place of Simulate in Main - drives whole simulation.
double SimOS::execute() { return 0.0; }

void SimOS::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  assert(processStates_.size() == 0 && "Multiple processes not yet supported");
  processStates_.push_back({.pid = 0,  // TODO: create unique PIDs
                            .path = process.getPath(),
                            .startBrk = process.getHeapStart(),
                            .currentBrk = process.getHeapStart(),
                            .initialStackPointer = process.getStackPointer(),
                            .mmapRegion = process.getMmapStart(),
                            .pageSize = process.getPageSize()});
  processStates_.back().fileDescriptorTable.push_back(STDIN_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDOUT_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDERR_FILENO);
}

uint64_t SimOS::getInitialStackPointer() const {
  assert(processStates_.size() > 0 &&
         "Attempted to retrieve a stack pointer before creating a process");

  return processStates_[0].initialStackPointer;
}

}  // namespace kernel
}  // namespace simeng