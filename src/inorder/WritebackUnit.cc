#include "WritebackUnit.hh"

namespace simeng {
namespace inorder {

WritebackUnit::WritebackUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromExecute,
    RegisterFileSet& registerFileSet)
    : fromExecuteBuffer(fromExecute), registerFileSet(registerFileSet) {}

void WritebackUnit::tick() {
  auto uop = fromExecuteBuffer.getHeadSlots()[0];

  if (uop == nullptr) {
    return;
  }

  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  for (size_t i = 0; i < results.size(); i++) {
    // Write results to register files
    registerFileSet.set(destinations[i], results[i]);
  }

  instructionsRetired++;

  fromExecuteBuffer.getHeadSlots()[0] = nullptr;
}

uint64_t WritebackUnit::getInstructionsRetiredCount() const {
  return instructionsRetired;
}

}  // namespace inorder
}  // namespace simeng
