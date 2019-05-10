#pragma once

#include "LinuxProcess.hh"

namespace simeng {
namespace kernel {

/** A state container for a Linux process. */
struct LinuxProcessState {
  /** The address of the start of process memory. */
  uint64_t processBrk;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class Linux {
 public:
  /** Create a new Linux process running above this kernel. */
  void createProcess(const LinuxProcess& process);

 private:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng
