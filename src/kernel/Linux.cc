#include "Linux.hh"

namespace simeng {
namespace kernel {

LinuxProcess::LinuxProcess(std::string path) : elf_(path) {}
uint64_t LinuxProcess::getHeapStart() const {
  return elf_.getProcessImage().size();
}

void Linux::createProcess(const LinuxProcess& process) {
  processStates_.push_back({process.getHeapStart()});
}

}  // namespace kernel
}  // namespace simeng
