#pragma once
#include <stdint.h>

namespace simeng {
namespace OS {

namespace defaults {
/** The Default PageSize for SimEng. */
static constexpr uint64_t page_size = 4096;
}  // namespace defaults

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
// is done keeping in mind that on current systems only lower 48bits of a
// virtual address are used. These lower 48 bits support an address space of
// approximately 282 tera bytes. Under any workload SimEng will never encounter
// larger address spaces than this.
//
// source
// https://stackoverflow.com/questions/6716946/why-do-x86-64-systems-have-only-a-48-bit-virtual-address-space#:~:text=They%20use%20an%20instruction%20set,be%20needed%20for%20many%20years.
namespace masks {
namespace faults {

namespace pagetable {
static constexpr uint64_t nofault = 0x0;
static constexpr uint64_t fault = 0x8000000000000000;
static constexpr uint64_t ignored = 0x3000000000000000;
static constexpr uint64_t translate = 0x4000000000000000;
static constexpr uint64_t map = 0x2000000000000000;
static constexpr uint64_t unmap = 0x1000000000000000;
static constexpr uint64_t dataAbort = 0x5000000000000000;
}  // namespace pagetable

static constexpr uint64_t getFaultCode(uint64_t value) {
  if ((value & masks::faults::pagetable::fault) != pagetable::fault)
    return masks::faults::pagetable::nofault;
  return (0x7000000000000000 & value) & 0xF000000000000000;
};

}  // namespace faults
}  // namespace masks
}  // namespace OS
}  // namespace simeng