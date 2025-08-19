#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace pipeline {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet,
    std::function<void(uint64_t insnId)> flagMicroOpCommits)
    : completionSlots_(completionSlots),
      registerFileSet_(registerFileSet),
      flagMicroOpCommits_(std::move(flagMicroOpCommits)) {}

void WritebackUnit::tick() {
  for (auto& completionSlot : completionSlots_) {
    auto uop = std::move(completionSlot.getHeadSlots()[0]);
    if (uop == nullptr) continue;

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < results.size(); i++) {
      // Skip offloaded registers
      if (uop->isRegisterOffloaded(destinations[i])) continue;

      // Write results to register file
      registerFileSet_.set(destinations[i], results[i]);
    }
    if (uop->isMicroOp()) {
      uop->setWaitingCommit();
      flagMicroOpCommits_(uop->getInstructionId());
      if (uop->isLastMicroOp()) instructionsWritten_++;
    } else {
      uop->setCommitReady();
      instructionsWritten_++;
    }
  }
}

uint64_t WritebackUnit::getInstructionsWrittenCount() const {
  return instructionsWritten_;
}

}  // namespace pipeline
}  // namespace simeng
