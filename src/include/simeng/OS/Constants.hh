#pragma once
#include <stdint.h>

#include <cstdint>

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

}  // namespace futexop
}  // namespace futex

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

/** This mask signifies that page table could not handle the page fault due the
 * virtual address not being in a valid address range. */
static constexpr uint64_t DATA_ABORT = 0x5000000000000000;

}  // namespace pagetable

/** This function returns true if value contains a fault code. */
static constexpr bool inFault(uint64_t value) {
  return (pagetable::FAULT & value) == pagetable::FAULT;
}

/** This function returns the fault code from a given uint64_t value. */
static constexpr uint64_t getFaultCode(uint64_t value) {
  if ((value & masks::faults::pagetable::FAULT) != pagetable::FAULT)
    return masks::faults::pagetable::NO_FAULT;
  return (0x7000000000000000 & value) & 0xF000000000000000;
};

}  // namespace faults
}  // namespace masks
}  // namespace OS
}  // namespace simeng
