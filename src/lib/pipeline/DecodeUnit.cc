#include "simeng/pipeline/DecodeUnit.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

DecodeUnit::DecodeUnit(PipelineBuffer<MacroOp>& input,
                       PipelineBuffer<std::shared_ptr<Instruction>>& output,
                       BranchPredictor& predictor)
    : input_(input), output_(output), predictor_(predictor){};

void DecodeUnit::tick() {
  if (output_.isStalled()) {
    input_.stall(true);
    return;
  }

  shouldFlush_ = false;
  input_.stall(false);

  for (size_t slot = 0; slot < input_.getWidth(); slot++) {
    auto& macroOp = input_.getHeadSlots()[slot];

    // Assume single uop per macro op for this version
    // TODO: Stall on multiple uops and siphon one per cycle, recording progress
    assert(macroOp.size() <= 1 &&
           "Multiple uops per macro-op not yet supported");

    if (macroOp.size() == 0) {
      // Nothing to process for this macro-op
      continue;
    }

    auto& uop = (output_.getTailSlots()[slot] = std::move(macroOp[0]));

    input_.getHeadSlots()[slot].clear();

    // Check preliminary branch prediction results now that the instruction is
    // decoded. Identifies:
    // - Non-branch instructions mistakenly predicted as branches
    // - Incorrect targets for immediate branches
    auto [misprediction, correctAddress] = uop->checkEarlyBranchMisprediction();
    if (misprediction) {
      earlyFlushes_++;
      shouldFlush_ = true;
      pc_ = correctAddress;

      if (!uop->isBranch()) {
        // Non-branch incorrectly predicted as a branch; let the predictor know
        predictor_.update(uop->getInstructionAddress(), false, pc_);
      }

      // Skip processing remaining macro-ops, as they need to be flushed
      break;
    }
  }
}

bool DecodeUnit::shouldFlush() const { return shouldFlush_; }
uint64_t DecodeUnit::getFlushAddress() const { return pc_; }
uint64_t DecodeUnit::getEarlyFlushes() const { return earlyFlushes_; };

}  // namespace pipeline
}  // namespace simeng
