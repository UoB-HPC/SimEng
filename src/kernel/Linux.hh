#pragma once

#include "../Elf.hh"

namespace simeng {
namespace kernel {

/** The initial state of a Linux process, constructed from a binary executable.
 */
class LinuxProcess {
 public:
  /** Construct a Linux process from an ELF file at `path`. */
  LinuxProcess(std::string path);

  /** Get the address of the start of the heap region. */
  uint64_t getHeapStart() const;

 private:
  /** The processed ELF file. */
  Elf elf_;
};

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
