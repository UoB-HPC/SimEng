#include "fetchUnit.hh"

namespace simeng {

FetchUnit::FetchUnit(PipelineBuffer<MacroOp> &toDecode, char* insnPtr, int programByteLength, Architecture* isa) : toDecode(toDecode), insnPtr(insnPtr), programByteLength(programByteLength), isa(isa) {
};

void FetchUnit::tick() {
    auto [macroop, bytesRead] = isa->predecode(insnPtr, 4, pc);

    pc += bytesRead;

    auto tail = toDecode.getTailSlots();
    tail[0] = macroop;

    if (pc >= programByteLength) {
        hasHalted_ = true;
    }
};

bool FetchUnit::hasHalted() const {
    return hasHalted_;
}

} // namespace simeng