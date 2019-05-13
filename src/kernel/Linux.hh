#pragma once

#include "LinuxProcess.hh"

namespace simeng {
namespace kernel {

/** A state container for a Linux process. */
struct LinuxProcessState {
  /** The address of the start of the heap. */
  uint64_t startBrk;
  /** The address of the current end of heap. */
  uint64_t currentBrk;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class Linux {
 public:
  /** Create a new Linux process running above this kernel. */
  void createProcess(const LinuxProcess& process);

  /** brk syscall: change data segment size. Sets the program break to `addr` if
   * reasonable, and returns the program break. */
  int64_t brk(uint64_t addr);

 private:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng
