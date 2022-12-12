#include "simeng/kernel/SimOS.hh"

namespace simeng {
namespace kernel {

SimOS::SimOS(int argc, char** argv)
    : syscalls_(SyscallHandler(processStates_)) {
  // Determine if a config file has been supplied.
  if (argc > 1) {
    configFilePath_ = std::string(argv[1]);
    // Determine if an executable has been supplied
    if (argc > 2) {
      executablePath_ = std::string(argv[2]);
      // Create a vector of any potential executable arguments from their
      // relative position within the argv variable
      int numberofArgs = argc - 3;
      executableArgs_ =
          std::vector<std::string>((argv + 3), (argv + 3) + numberofArgs);
    }
  }
}

// UPDATE
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

// UPDATE
uint64_t SimOS::getInitialStackPointer() const {
  assert(processStates_.size() > 0 &&
         "Attempted to retrieve a stack pointer before creating a process");

  return processStates_[0].initialStackPointer;
}

}  // namespace kernel
}  // namespace simeng