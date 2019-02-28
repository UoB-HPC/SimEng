#include "WritebackUnit.hh"

namespace simeng {
namespace outoforder {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet)
    : completionSlots(completionSlots), registerFileSet(registerFileSet) {}

void WritebackUnit::tick() {
  for (size_t slot = 0; slot < completionSlots.size(); slot++) {
    auto& uop = completionSlots[slot].getHeadSlots()[0];

    if (uop == nullptr) {
      continue;
    }

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < results.size(); i++) {
      // Write results to register file
      registerFileSet.set(destinations[i], results[i]);
    }
    uop->setCommitReady();

    instructionsRetired++;

    completionSlots[slot].getHeadSlots()[0] = nullptr;
  }
}

uint64_t WritebackUnit::getInstructionsRetiredCount() const {
  return instructionsRetired;
}

}  // namespace outoforder
}  // namespace simeng
