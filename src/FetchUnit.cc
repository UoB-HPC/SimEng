#include "FetchUnit.hh"

#include <iostream>

namespace simeng {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp>& toDecode, char* insnPtr, unsigned int programByteLength, Architecture& isa) : toDecode(toDecode), insnPtr(insnPtr), programByteLength(programByteLength), isa(isa) {
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

    auto [macroop, bytesRead] = isa.predecode(insnPtr + pc, 4, pc);

    pc += bytesRead;

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
