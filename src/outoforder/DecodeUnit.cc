#include "DecodeUnit.hh"

#include <cassert>

namespace simeng {
namespace outoforder {

DecodeUnit::DecodeUnit(PipelineBuffer<MacroOp>& fromFetch,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
                       BranchPredictor& predictor)
    : fromFetchBuffer(fromFetch),
      toExecuteBuffer(toExecute),
      predictor(predictor){};

void DecodeUnit::tick() {
  if (toExecuteBuffer.isStalled()) {
    fromFetchBuffer.stall(true);
    return;
  }

  shouldFlush_ = false;
  fromFetchBuffer.stall(false);

  auto& macroOp = fromFetchBuffer.getHeadSlots()[0];

  // Assume single uop per macro op for this version
  // TODO: Stall on multiple uops and siphon one per cycle, recording progress
  assert(macroOp.size() <= 1 && "Multiple uops per macro-op not yet supported");

  if (macroOp.size() == 0) {
    // Nothing to process
    return;
  }

  auto& uop = macroOp[0];

  // Check preliminary branch prediction results now that the instruction is
  // decoded. Identifies:
  // - Non-branch instructions mistakenly predicted as branches
  // - Incorrect targets for immediate branches
  auto [misprediction, correctAddress] = uop->checkEarlyBranchMisprediction();
  if (misprediction) {
    shouldFlush_ = true;
    pc = correctAddress;

    if (!uop->isBranch()) {
      // Non-branch incorrectly predicted as a branch; let the predictor know
      predictor.update(uop->getInstructionAddress(), false, pc);
    }
  }

  toExecuteBuffer.getTailSlots()[0] = uop;
  fromFetchBuffer.getHeadSlots()[0].clear();
}

bool DecodeUnit::shouldFlush() const { return shouldFlush_; }
uint64_t DecodeUnit::getFlushAddress() const { return pc; }

}  // namespace outoforder
}  // namespace simeng
