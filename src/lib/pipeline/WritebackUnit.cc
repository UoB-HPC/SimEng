#include "simeng/pipeline/WritebackUnit.hh"

#include <iostream>

namespace simeng {
namespace pipeline {

WritebackUnit::WritebackUnit(
    std::vector<PipelineBuffer<std::shared_ptr<Instruction>>>& completionSlots,
    RegisterFileSet& registerFileSet,
    std::function<void(Register reg)> setRegisterReady,
    std::function<bool(uint64_t seqId)> canWriteback,
    std::function<void(const std::shared_ptr<Instruction>&)> postWriteback)
    : completionSlots_(completionSlots),
      registerFileSet_(registerFileSet),
      setRegisterReady_(setRegisterReady),
      canWriteback_(canWriteback),
      postWriteback_(postWriteback) {}

void WritebackUnit::tick() {
  for (size_t slot = 0; slot < completionSlots_.size(); slot++) {
    auto& uop = completionSlots_[slot].getHeadSlots()[0];

    completionSlots_[slot].stall(false);

    if (uop == nullptr) {
      continue;
    }
    // Query if the uop can be written back; if not, stall the completion slot
    // until it can be
    if (!canWriteback_(uop->getSequenceId())) {
      completionSlots_[slot].stall(true);
      continue;
    }

    auto& results = uop->getResults();
    auto& destinations = uop->getDestinationRegisters();
    for (size_t i = 0; i < results.size(); i++) {
      // Write results to register file
      registerFileSet_.set(destinations[i], results[i]);
      // Set the register as ready to be read from the register fileset
      setRegisterReady_(destinations[i]);
    }

    // Carry out core/model specific functionality after the uops writeback has
    // been complete
    postWriteback_(uop);

    if (uop->isLastMicroOp()) instructionsWritten_++;

    completionSlots_[slot].getHeadSlots()[0] = nullptr;
  }
}

uint64_t WritebackUnit::getInstructionsWrittenCount() const {
  return instructionsWritten_;
}

void WritebackUnit::flush() {
  for (size_t i = 0; i < completionSlots_.size(); i++) {
    completionSlots_[i].fill(nullptr);
    completionSlots_[i].stall(false);
  }
}

}  // namespace pipeline
}  // namespace simeng
