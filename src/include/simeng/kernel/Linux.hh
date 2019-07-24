#pragma once

#include "simeng/kernel/LinuxProcess.hh"

namespace simeng {
namespace kernel {

/** A state container for a Linux process. */
struct LinuxProcessState {
  /** The process ID. */
  int64_t pid;
  /** The path of the executable that created this process. */
  std::string path;
  /** The address of the start of the heap. */
  uint64_t startBrk;
  /** The address of the current end of heap. */
  uint64_t currentBrk;
  /** The initial stack pointer. */
  uint64_t initialStackPointer;

  // Thread state
  // TODO: Support multiple threads per process
  /** The clear_child_tid value. */
  uint64_t clearChildTid = 0;
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

  /** clock_gettime syscall: get the time of specified clock `clkId`, using
   * the system timer `systemTimer` (with nanosecond accuracy). Returns 0 on
   * success, and puts the retrieved time in the `seconds` and `nanoseconds`
   * arguments. */
  uint64_t clockGetTime(uint64_t clkId, uint64_t systemTimer, uint64_t& seconds,
                        uint64_t& nanoseconds);

  /** getpid syscall: get the process owner's process ID. */
  int64_t getpid() const;
  /** getuid syscall: get the process owner's user ID. */
  int64_t getuid() const;
  /** geteuid syscall: get the process owner's effective user ID. */
  int64_t geteuid() const;
  /** getgid syscall: get the process owner's group ID. */
  int64_t getgid() const;
  /** getegid syscall: get the process owner's effective group ID. */
  int64_t getegid() const;

  /** readlinkat syscall: read value of a symbolic link. */
  int64_t readlinkat(int64_t dirfd, const std::string pathname, char* buf,
                     size_t bufsize) const;

  /** set_tid_address syscall: set clear_child_tid value for calling thread. */
  int64_t setTidAddress(uint64_t tidptr);

  /** The maximum size of a filesystem path. */
  static const size_t LINUX_PATH_MAX = 4096;

 private:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng
