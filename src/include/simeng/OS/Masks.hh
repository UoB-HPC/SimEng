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

static constexpr uint64_t getFaultCode(uint64_t value) {
  return (0x7000000000000000 & value) & masks::get::fault;
};

namespace pagetable {
static const uint64_t fault = 0x8000000000000000;
static const uint64_t translate = 0x4000000000000000;
static const uint64_t map = 0x2000000000000000;
static const uint64_t unmap = 0x1000000000000000;
static const uint64_t speculation = 0x5000000000000000;
}  // namespace pagetable
}  // namespace faults

}  // namespace masks

}  // namespace kernel
}  // namespace simeng

#define FAULTCODE(X)
