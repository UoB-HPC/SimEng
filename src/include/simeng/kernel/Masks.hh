#pragma once
#include <stdint.h>

namespace simeng {
namespace kernel {

namespace masks {

namespace get {
static const uint64_t addr = 0x0FFFFFFFFFFFFFFF;
static const uint64_t fault = 0xF000000000000000;
}  // namespace get

namespace faults {

namespace pagetable {
static const uint64_t nofault = 0x0;
static const uint64_t fault = 0x8000000000000000;
static const uint64_t ignored = 0x3000000000000000;
static const uint64_t translate = 0x4000000000000000;
static const uint64_t map = 0x2000000000000000;
static const uint64_t unmap = 0x1000000000000000;
static const uint64_t dataAbort = 0x5000000000000000;
}  // namespace pagetable

static constexpr uint64_t getFaultCode(uint64_t value) {
  if ((value & masks::faults::pagetable::fault) != pagetable::fault)
    return masks::faults::pagetable::nofault;
  return (0x7000000000000000 & value) & masks::get::fault;
};

}  // namespace faults
}  // namespace masks
}  // namespace kernel
}  // namespace simeng

#define FAULTCODE(X)
