#pragma once

#include <stdint.h>

namespace simeng {
namespace OS {

namespace defaults {

/** The default PageSize for SimEng. */
static constexpr uint64_t PAGE_SIZE = 4096;

/** The maximum number of file descriptors a process can have,as defined by the
 * linux kernel.*/
static constexpr uint64_t MAX_FD_NUM = 1024;

}  // namespace defaults

/**The syscall constants are mainly used in MemRegion to ensure we are
 * consistently using the Linux specific definitions of certain syscall
 * arguments, regardless of the host Operating System SimEng is being run on. */
namespace syscalls {
namespace prlimit {
/** Value denoting an infinite limit on an associated attribute.*/
static constexpr uint64_t RLIM_INF = 0xffffffffffffffff;
}  // namespace prlimit

namespace mmap {
namespace prot {

/** Page can be read. */
static constexpr int READ = 0x1;

/** Page can be written. */
static constexpr int WRITE = 0x2;

/** Page can be executed. */
static constexpr int EXEC = 0x4;

/** Page can not be accessed. */
static constexpr int NONE = 0x0;

}  // namespace prot

namespace flags {

/** Share MMAP changes. */
static constexpr int SIMENG_MAP_SHARED = 0x01;

/** MMAP changes are private. */
static constexpr int SIMENG_MAP_PRIVATE = 0x02;

/** Interpret addr directly */
static constexpr int SIMENG_MAP_FIXED = 0x10;

}  // namespace flags
}  // namespace mmap

namespace futex {
namespace futexop {
/** This futex flag signifies a private operation. It is OR'ed with other futex
 * operation flags. */
static constexpr int SIMENG_FUTEX_PRIVATE_FLAG = 128;

/** This futex operation signifies that the invoking process should be put to
 * sleep. */
static constexpr int SIMENG_FUTEX_WAIT = 0;

/** This futex operation signifies that processes sleeping on a futex should be
 * awakened. */
static constexpr int SIMENG_FUTEX_WAKE = 1;

/** This futex operation also signifies that processes sleeping on a futex
 should be awakened. It also tells the kernel that the futex is process-private
 and not shared with another process (i.e., it is being used for synchronization
 only between threads of the same process). */
static constexpr int SIMENG_FUTEX_WAKE_PRIVATE =
    (SIMENG_FUTEX_WAKE | SIMENG_FUTEX_PRIVATE_FLAG);

static constexpr int SIMENG_FUTEX_WAIT_PRIVATE =
    (SIMENG_FUTEX_WAIT | SIMENG_FUTEX_PRIVATE_FLAG);

}  // namespace futexop
}  // namespace futex

namespace clone {
/** Declare all flags used for `clone` system call. */
namespace flags {
/** Signified that the child process should run in the same memory space as the
 * calling process. */
static constexpr int f_CLONE_VM = 0x00000100;

/** Signifies that the caller and child process share the same filesystem
 * information. */
static constexpr int f_CLONE_FS = 0x00000200;

/** Signifies that the calling process and child process share the same file
 * descriptor table. */
static constexpr int f_CLONE_FILES = 0x00000400;

/** Signifies that the calling process and child process share the same table of
 * signal handlers. */
static constexpr int f_CLONE_SIGHAND = 0x00000800;

/** Signifies that a PID file descriptor referring to the child process is
 * allocated and placed at a specified location in the parent's memory. */
static constexpr int f_CLONE_PIDFD = 0x00001000;

/** Signifies that the child process is to be traced IF calling process is
 * currently being traced. */
static constexpr int f_CLONE_PTRACE = 0x00002000;

/** Signifies that the execution of the calling process is suspended until the
 * child releases its virtual memory resources. */
static constexpr int f_CLONE_VFORK = 0x00004000;

/** Signifies that the parent of the child process will be the same as the
 * calling process. */
static constexpr int f_CLONE_PARENT = 0x00008000;

/** Signifies that the child is placed into the same thread group as the calling
 * process. */
static constexpr int f_CLONE_THREAD = 0x00010000;

/** Signifies that the child process is started in a new mount namespace. */
static constexpr int f_CLONE_NEWNS = 0x00020000;

/** Signifies that the child and calling process share a single list of Syste V
 * semaphore adjustment values. */
static constexpr int f_CLONE_SYSVSEM = 0x00040000;

/** Signifies that the Thread Local Storage descriptor is set to the specified
 * value. */
static constexpr int f_CLONE_SETTLS = 0x00080000;

/** Signifies that the child's TID will be stored in the parent's memory. */
static constexpr int f_CLONE_PARENT_SETTID = 0x00100000;

/** Signifies that the child TID should be cleared when child exits. */
static constexpr int f_CLONE_CHILD_CLEARTID = 0x00200000;

/** Signifies that the parent should not recieve a signal when child terminates.
 */
static constexpr int f_CLONE_DETACHED = 0x00400000;

/** Signifies that a tracing process cannot force `CLONE_PTRACE` on this child
 * process. */
static constexpr int f_CLONE_UNTRACED = 0x00800000;

/** Signifies that the child TID shhould be stored in child memory when the
 * child exits. */
static constexpr int f_CLONE_CHILD_SETTID = 0x01000000;

/** Signifies that the child process be created in a new cgroup namespace. */
static constexpr int f_CLONE_NEWCGROUP = 0x02000000;

/** Signifies that the child process is created in a new UTS namespace. */
static constexpr int f_CLONE_NEWUTS = 0x04000000;

/** Signifies that the child process is created in a new IPC namespace. */
static constexpr int f_CLONE_NEWIPC = 0x08000000;

/** Signifies that the child process is created in a new user namespace. */
static constexpr int f_CLONE_NEWUSER = 0x10000000;

/** Signifies that the child process is created in a new PID namespace. */
static constexpr int f_CLONE_NEWPID = 0x20000000;

/** Signifies that the child process is created in a new network namespace. */
static constexpr int f_CLONE_NEWNET = 0x40000000;

/** Signifies that the child process shares and I/O context with the calling
 * process. */
static constexpr int f_CLONE_IO = 0x80000000;
}  // namespace flags
}  // namespace clone

}  // namespace syscalls

// Currently only the top 4 bits are used to signal a fault with addresses. This
// is done keeping in mind that on current systems only the lower 52 bits of a
// virtual address are used. These lower 52 bits support an address space of
// approximately 562 terabytes. This specification is also followed in the Linux
// Kernel. source: https://opensource.com/article/20/12/52-bit-arm64-kernel

namespace masks {
namespace faults {

namespace pagetable {

/** This mask signifies no fault in pagetable. */
static constexpr uint64_t NO_FAULT = 0x0;

/** This mask signifies that there is a fault in the pagetable. */
static constexpr uint64_t FAULT = 0x8000000000000000;

/** This mask signifies that the virtual address should be ignored */
static constexpr uint64_t IGNORED = 0x3000000000000000;

/** This mask signifies that the virtual address translation does not exist in
 * the page table. */
static constexpr uint64_t TRANSLATE = 0x4000000000000000;

/** This mask signifies that the virtual address mapping was not successful. */
static constexpr uint64_t MAP = 0x2000000000000000;

/** This mask signifies that the virtual address unmapping was not successful.
 */
static constexpr uint64_t UNMAP = 0x1000000000000000;

/** This mask signifies that the page table could not handle the page fault due
 * the virtual address not being in a valid address range. */
static constexpr uint64_t DATA_ABORT = 0x5000000000000000;

}  // namespace pagetable

/** This function returns true if value contains a fault code. */
static constexpr bool hasFault(uint64_t value) {
  return (pagetable::FAULT & value) == pagetable::FAULT;
}

/** This function returns the fault code from a given uint64_t value. */
static constexpr uint64_t getFaultCode(uint64_t value) {
  if ((value & masks::faults::pagetable::FAULT) != pagetable::FAULT)
    return masks::faults::pagetable::NO_FAULT;
  return (0x7000000000000000 & value);
}

/** Function to print the fault code in a human friendly manner. */
static constexpr char* printFault(uint64_t value) {
  switch (getFaultCode(value)) {
    case masks::faults::pagetable::NO_FAULT:
      return const_cast<char*>("NO_FAULT : No Fault has occured.");
      break;
    case masks::faults::pagetable::IGNORED:
      return const_cast<char*>("IGNORED : Address should be ignored.");
      break;
    case masks::faults::pagetable::TRANSLATE:
      return const_cast<char*>(
          "TRANSLATE : The virtual address translation does not exist "
          "in the page table.");
      break;
    case masks::faults::pagetable::MAP:
      return const_cast<char*>(
          "MAP : The virtual address mapping was not successful.");
      break;
    case masks::faults::pagetable::UNMAP:
      return const_cast<char*>(
          "UNMAP : The virtual address unmapping was not successful.");
      break;
    case masks::faults::pagetable::DATA_ABORT:
      return const_cast<char*>(
          "DATA_ABORT : Address not in valid address range.");
      break;
    default:
      return const_cast<char*>("UNKNOWN.");
      break;
  }
}

}  // namespace faults
}  // namespace masks
}  // namespace OS
}  // namespace simeng
