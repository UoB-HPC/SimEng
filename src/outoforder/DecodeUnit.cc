#include "DecodeUnit.hh"

#include <cassert>

namespace simeng {
namespace outoforder {

DecodeUnit::DecodeUnit(
    PipelineBuffer<MacroOp>& fromFetch,
    PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchIssue,
    BranchPredictor& predictor)
    : fromFetchBuffer(fromFetch),
      toDispatchIssueBuffer(toDispatchIssue),
      predictor(predictor){};

void DecodeUnit::tick() {
  if (toDispatchIssueBuffer.isStalled()) {
    fromFetchBuffer.stall(true);
    return;
  }

  shouldFlush_ = false;
  fromFetchBuffer.stall(false);

  for (size_t slot = 0; slot < fromFetchBuffer.getWidth(); slot++) {
    auto& macroOp = fromFetchBuffer.getHeadSlots()[slot];

    // Assume single uop per macro op for this version
    // TODO: Stall on multiple uops and siphon one per cycle, recording progress
    assert(macroOp.size() <= 1 &&
           "Multiple uops per macro-op not yet supported");

    if (macroOp.size() == 0) {
      // Nothing to process for this macro-op
      continue;
    }

    auto& uop = macroOp[0];

    toDispatchIssueBuffer.getTailSlots()[slot] = uop;
    fromFetchBuffer.getHeadSlots()[slot].clear();

    // Check preliminary branch prediction results now that the instruction is
    // decoded. Identifies:
    // - Non-branch instructions mistakenly predicted as branches
    // - Incorrect targets for immediate branches
    auto [misprediction, correctAddress] = uop->checkEarlyBranchMisprediction();
    if (misprediction) {
      earlyFlushes++;
      shouldFlush_ = true;
      pc = correctAddress;

      if (!uop->isBranch()) {
        // Non-branch incorrectly predicted as a branch; let the predictor know
        predictor.update(uop->getInstructionAddress(), false, pc);
      }

      // Skip processing remaining macro-ops, as they need to be flushed
      break;
    }
  }
}

bool DecodeUnit::shouldFlush() const { return shouldFlush_; }
uint64_t DecodeUnit::getFlushAddress() const { return pc; }
uint64_t DecodeUnit::getEarlyFlushes() const { return earlyFlushes; };

}  // namespace outoforder
}  // namespace simeng
