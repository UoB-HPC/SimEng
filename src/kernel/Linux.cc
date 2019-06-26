#include "Linux.hh"

#include <cassert>

namespace simeng {
namespace kernel {

void Linux::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  processStates_.push_back({.startBrk = process.getHeapStart(),
                            .currentBrk = process.getHeapStart(),
                            .initialStackPointer = process.getStackPointer()});
}

uint64_t Linux::getInitialStackPointer() const {
  assert(processStates_.size() > 0 &&
         "Attempted to retrieve a stack pointer before creating a process");

  return processStates_[0].initialStackPointer;
}

int64_t Linux::brk(uint64_t address) {
  assert(processStates_.size() > 0 &&
         "Attempted to move the program break before creating a process");

  auto& state = processStates_[0];
  // Move the break if it's within the heap region
  if (address > state.startBrk) {
    state.currentBrk = address;
  }
  return state.currentBrk;
}

int64_t Linux::getuid() const { return 0; }
int64_t Linux::geteuid() const { return 0; }
int64_t Linux::getgid() const { return 0; }
int64_t Linux::getegid() const { return 0; }

}  // namespace kernel
}  // namespace simeng
