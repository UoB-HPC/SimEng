#include "FetchUnit.hh"

namespace simeng {
namespace outoforder {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& toDecode, const char* insnPtr,
                     unsigned int programByteLength, const Architecture& isa,
                     BranchPredictor& branchPredictor)
    : toDecode(toDecode),
      insnPtr(insnPtr),
      programByteLength(programByteLength),
      isa(isa),
      branchPredictor(branchPredictor){};

void FetchUnit::tick() {
  if (toDecode.isStalled()) {
    return;
  }

  auto outputSlots = toDecode.getTailSlots();
  for (size_t slot = 0; slot < toDecode.getWidth(); slot++) {
    if (hasHalted_) {
      // PC is outside instruction memory region; do nothing
      break;
    }

    auto& macroOp = outputSlots[slot];

    auto prediction = branchPredictor.predict(pc);
    auto bytesRead = isa.predecode(insnPtr + pc, 4, pc, prediction, macroOp);

    if (!prediction.taken) {
      // Predicted as not taken; increment PC to next instruction
      pc += bytesRead;
    } else {
      // Predicted as taken; set PC to predicted target address
      pc = prediction.target;
    }

    if (pc >= programByteLength) {
      hasHalted_ = true;
      break;
    }

    if (prediction.taken) {
      if (slot + 1 < toDecode.getWidth()) {
        branchStalls++;
      }
      // Can't continue fetch immediately after a branch
      break;
    }
  }
};

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc = address;
  hasHalted_ = (pc >= programByteLength);
}

uint64_t FetchUnit::getBranchStalls() const { return branchStalls; }

}  // namespace outoforder
}  // namespace simeng
