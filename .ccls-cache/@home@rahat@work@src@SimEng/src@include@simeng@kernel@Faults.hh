#include <stdint.h>
namespace simeng {
namespace kernel {
namespace masks {
namespace get {

static const uint64_t addr = 0x0FFFFFFFFFFFFFFF;
static const uint64_t fault = 0xF000000000000000;

};

namespace ptfaults {
static const uint64_t fault = 0x8000000000000000;
static const uint64_t translate = 0x4000000000000000;
static const uint64_t map = 0x2000000000000000;
static const uint64_t unmap = 0x1000000000000000;
};

}  // namespace kernel
}  // namespace simeng
