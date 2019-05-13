#include "Linux.hh"

#include <cassert>

namespace simeng {
namespace kernel {

void Linux::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  processStates_.push_back({process.getHeapStart(), process.getHeapStart()});
}

int64_t Linux::brk(uint64_t address) {
  auto& state = processStates_[0];
  // Move the break if it's within the heap region
  if (address > state.startBrk) {
    state.currentBrk = address;
  }
  return state.currentBrk;
}

}  // namespace kernel
}  // namespace simeng
