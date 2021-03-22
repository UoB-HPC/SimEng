#include "simeng/pipeline/WritebackUnit.hh"

#include <iostream>

namespace simeng {
namespace pipeline {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet,
    std::function<void(uint64_t insnId)> flagMicroOpCommits)
    : completionSlots_(completionSlots),
      registerFileSet_(registerFileSet),
      flagMicroOpCommits_(flagMicroOpCommits) {}

unsigned int WritebackUnit::tick() {
  unsigned int written = 0;
  for (size_t slot = 0; slot < completionSlots_.size(); slot++) {
    auto& uop = completionSlots_[slot].getHeadSlots()[0];

    if (uop == nullptr) {
      continue;
    }

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < results.size(); i++) {
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

    written++;

    completionSlots_[slot].getHeadSlots()[0] = nullptr;
  }
  return written;
}

uint64_t WritebackUnit::getInstructionsWrittenCount() const {
  return instructionsWritten_;
}

}  // namespace pipeline
}  // namespace simeng
