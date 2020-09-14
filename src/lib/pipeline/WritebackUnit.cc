#include "simeng/pipeline/WritebackUnit.hh"
#include <iostream>

namespace simeng {
namespace pipeline {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet)
    : completionSlots_(completionSlots), registerFileSet_(registerFileSet) {}

void WritebackUnit::tick() {
  // std::cout << "=====================\nWB output: ";
  for (size_t slot = 0; slot < completionSlots_.size(); slot++) {
    auto& uop = completionSlots_[slot].getHeadSlots()[0];

    if (uop == nullptr) {
      continue;
    }
    // std::cout << std::hex << uop->getInstructionAddress() << std::dec;

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < results.size(); i++) {
      // Write results to register file
      registerFileSet_.set(destinations[i], results[i]);
    }
    uop->setCommitReady();

    instructionsWritten_++;
    // std::cout << ", ";
    completionSlots_[slot].getHeadSlots()[0] = nullptr;
  }
  // std::cout << std::endl;
}

uint64_t WritebackUnit::getInstructionsWrittenCount() const {
  return instructionsWritten_;
}

}  // namespace pipeline
}  // namespace simeng
