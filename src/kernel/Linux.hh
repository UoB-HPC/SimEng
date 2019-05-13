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
  /** The initial stack pointer. */
  uint64_t initialStackPointer;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class Linux {
 public:
  /** Create a new Linux process running above this kernel. */
  void createProcess(const LinuxProcess& process);

  /** Retrieve the initial stack pointer. */
  uint64_t getInitialStackPointer() const;

  /** brk syscall: change data segment size. Sets the program break to
   * `addr` if reasonable, and returns the program break. */
  int64_t brk(uint64_t addr);

  /** getuid syscall: get the process owner's user ID. */
  int64_t getuid() const;
  /** geteuid syscall: get the process owner's effective user ID. */
  int64_t geteuid() const;
  /** getgid syscall: get the process owner's group ID. */
  int64_t getgid() const;
  /** getegid syscall: get the process owner's effective group ID. */
  int64_t getegid() const;

 private:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng
