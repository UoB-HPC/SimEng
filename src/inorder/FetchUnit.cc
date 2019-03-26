#include "FetchUnit.hh"

namespace simeng {
namespace inorder {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& toDecode, const char* insnPtr,
                     unsigned int programByteLength, uint64_t entryPoint,
                     const Architecture& isa, BranchPredictor& branchPredictor)
    : toDecode(toDecode),
      pc(entryPoint),
      insnPtr(insnPtr),
      programByteLength(programByteLength),
      isa(isa),
      branchPredictor(branchPredictor){};

void FetchUnit::tick() {
  if (toDecode.isStalled()) {
    return;
  }

  if (hasHalted_) {
    // PC is outside instruction memory region; do nothing
    return;
  }

  auto& macroOp = toDecode.getTailSlots()[0];

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
  }
};

bool FetchUnit::hasHalted() const { return hasHalted_; }

void FetchUnit::updatePC(uint64_t address) {
  pc = address;
  hasHalted_ = (pc >= programByteLength);
}

}  // namespace inorder
}  // namespace simeng
