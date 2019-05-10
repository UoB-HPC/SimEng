#include "Linux.hh"

#include <cassert>

namespace simeng {
namespace kernel {

void Linux::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  processStates_.push_back({process.getHeapStart()});
}

}  // namespace kernel
}  // namespace simeng
