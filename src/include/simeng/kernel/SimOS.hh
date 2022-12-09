#pragma once

#include <vector>

// #include "simeng/CoreInstance.hh"
#include "simeng/kernel/SyscallHandler.hh"

namespace simeng {
namespace kernel {

/** A simple, lightweight Operating System kernel based on Linux to emulate
 * syscalls and manage process execution. */
class SimOS {
 public:
  /** Construct a SimOS object. */
  SimOS(/*const std::vector<std::string>& commandLine, YAML::Node config*/);

  /** Execute the target workload through SimEng. */
  double execute();

  /** Create the desired amount of Core's. */
  void createCores(const uint64_t numCores);

  /** Create a new Linux process running above this kernel. */
  /// EDIT
  void createProcess(const LinuxProcess& process);

  /** Retrieve the initial stack pointer. */
  /// EDIT
  uint64_t getInitialStackPointer() const;

  /** SyscallHandler Object to process all syscalls. */
  SyscallHandler syscalls_;

  /** The maximum size of a filesystem path. */
  static const size_t LINUX_PATH_MAX = 4096;

 private:
  /** The list of available CPU cores*/
  // std::vector<CoreInstance> cores_;

  /** The list of active processes. */
  std::vector<std::shared_ptr<LinuxProcess>> processes_;

  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng