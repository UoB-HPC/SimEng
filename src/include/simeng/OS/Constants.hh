#pragma once
#include <stdint.h>

namespace simeng {
namespace OS {

namespace defaults {

/** The Default PageSize for SimEng. */
static constexpr uint64_t page_size = 4096;

/** The maximum number of file descriptors a process can have,as defined by the
 * linux kernel.*/
static constexpr uint64_t maxFdNum = 1024;

}  // namespace defaults

/** These syscall constants are mainly used in MemRegion to ensure we are
 * consistent will linux specific definitions in different Operating systems. */
namespace syscalls {
namespace mmap {
namespace prot {

/** Page can be read. */
static constexpr int read = 0x1;

/** Page can be written. */
static constexpr int write = 0x2;

/** Page can be executed. */
static constexpr int exec = 0x4;

/** Page can not be accessed. */
static constexpr int none = 0x0;

}  // namespace prot

namespace flags {

/** Share MMAP changes. */
static constexpr int map_shared = 0x01;

/** MMAP changes are private. */
static constexpr int map_private = 0x02;

/** Interpret addr directly */
static constexpr int map_fixed = 0x10;

}  // namespace flags
}  // namespace mmap
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
static constexpr uint64_t nofault = 0x0;

/** This mask signifies that there is a fault in the pagetable. */
static constexpr uint64_t fault = 0x8000000000000000;

/** This mask signifies that the virtual address should be ignored */
static constexpr uint64_t ignored = 0x3000000000000000;

/** This mask signifies that the virtual address translation does not exist in
 * the page table. */
static constexpr uint64_t translate = 0x4000000000000000;

/** This mask signifies that the virtual address mapping was not successful. */
static constexpr uint64_t map = 0x2000000000000000;

/** This mask signifies that the virtual address unmapping was not successful.
 */
static constexpr uint64_t unmap = 0x1000000000000000;

/** This mask signifies that page table could not handle the page fault due the
 * virtual address not being in a valid address range. */
static constexpr uint64_t dataAbort = 0x5000000000000000;

}  // namespace pagetable

/** This function returns the fault code from a given uint64_t value. */
static constexpr uint64_t getFaultCode(uint64_t value) {
  if ((value & masks::faults::pagetable::fault) != pagetable::fault)
    return masks::faults::pagetable::nofault;
  return (0x7000000000000000 & value) & 0xF000000000000000;
};

}  // namespace faults
}  // namespace masks
}  // namespace OS
}  // namespace simeng
