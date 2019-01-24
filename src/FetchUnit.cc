#include "FetchUnit.hh"

#include <iostream>

namespace simeng {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& toDecode, char* insnPtr, unsigned int programByteLength, Architecture& isa, BranchPredictor& branchPredictor) : toDecode(toDecode), insnPtr(insnPtr), programByteLength(programByteLength), isa(isa), branchPredictor(branchPredictor) {
};

void FetchUnit::tick() {
    if (toDecode.isStalled()) {
        return;
    }

    auto out = toDecode.getTailSlots();
    if (pc >= programByteLength) {
        out[0] = {};
        return;
    }

    auto prediction = branchPredictor.predict(pc);
    auto [macroop, bytesRead] = isa.predecode(insnPtr + pc, 4, pc, prediction);

    if (!prediction.taken) {
        pc += bytesRead;
    } else {
        pc = prediction.target;
    }

    out[0] = macroop;

    if (pc >= programByteLength) {
        hasHalted_ = true;
    }
};

bool FetchUnit::hasHalted() const {
    return hasHalted_;
}

void FetchUnit::updatePC(uint64_t address) {
    pc = address;
}

} // namespace simeng
