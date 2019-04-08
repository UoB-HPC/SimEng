#include "FetchUnit.hh"

namespace simeng {
namespace pipeline {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& output, const char* insnPtr,
                     unsigned int programByteLength, uint64_t entryPoint,
                     const Architecture& isa, BranchPredictor& branchPredictor)
    : output_(output),
      pc_(entryPoint),
      insnPtr_(insnPtr),
      programByteLength_(programByteLength),
      isa_(isa),
      branchPredictor_(branchPredictor){};

void FetchUnit::tick() {
  if (output_.isStalled()) {
    return;
  }

  auto outputSlots = output_.getTailSlots();
  for (size_t slot = 0; slot < output_.getWidth(); slot++) {
    if (hasHalted_) {
      // PC is outside instruction memory region; do nothing
      break;
    }

    auto& macroOp = outputSlots[slot];

    auto prediction = branchPredictor_.predict(pc_);
    auto bytesRead =
        isa_.predecode(insnPtr_ + pc_, 4, pc_, prediction, macroOp);

    if (!prediction.taken) {
      // Predicted as not taken; increment PC to next instruction
      pc_ += bytesRead;
    } else {
      // Predicted as taken; set PC to predicted target address
      pc_ = prediction.target;
    }

    if (pc_ >= programByteLength_) {
      hasHalted_ = true;
      break;
    }

    if (prediction.taken) {
      if (slot + 1 < output_.getWidth()) {
        branchStalls_++;
      }
      // Can't continue fetch immediately after a branch
      break;
    }
  }
};

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc_ = address;
  hasHalted_ = (pc_ >= programByteLength_);
}

uint64_t FetchUnit::getBranchStalls() const { return branchStalls_; }

}  // namespace pipeline
}  // namespace simeng
