#include "DecodeUnit.hh"

#include <iostream>
#include <cassert>

namespace simeng {

DecodeUnit::DecodeUnit(PipelineBuffer<MacroOp>& fromFetch, PipelineBuffer<std::shared_ptr<Instruction>>& toExecute, RegisterFile& registerFile) : fromFetchBuffer(fromFetch), toExecuteBuffer(toExecute), registerFile(registerFile) {};

void DecodeUnit::tick() {

  if (toExecuteBuffer.isStalled()) {
    fromFetchBuffer.stall(true);
    return;
  }
  
  shouldFlush_ = false;
  fromFetchBuffer.stall(false);
  
  auto macroOp = fromFetchBuffer.getHeadSlots()[0];

  // Assume single uop per macro op for this version
  // TODO: Stall on multiple uops and siphon one per cycle, recording progress
  auto out = toExecuteBuffer.getTailSlots();

  if (macroOp.size() == 0) {
    // Nothing to process
    out[0] = nullptr;
  } else {
    auto uop = macroOp[0];

    // Check preliminary branch prediction results now that the instruction is decoded
    // Identifies:
    // - Non-branch instructions mistakenly predicted as branches
    // - Incorrect targets for immediate branches
    auto [misprediction, correctAddress] = uop->checkEarlyBranchMisprediction();
    if (misprediction) {
      shouldFlush_ = true;
      pc = correctAddress;
    }

    out[0] = uop;
  }

  fromFetchBuffer.getHeadSlots()[0] = {};
}

void DecodeUnit::forwardOperands(std::vector<Register> registers, std::vector<RegisterValue> values) {
  assert(registers.size() == values.size() && "Mismatched register and value vector sizes");

  auto uop = toExecuteBuffer.getTailSlots()[0];
  if (uop == nullptr) {
    return;
  }
  if (uop->canExecute()) {
    return;
  }

  for (size_t i = 0; i < registers.size(); i++) {
    uop->supplyOperand(registers[i], values[i]);
  }

  // Register read
  // Identify remaining missing registers and supply values
  auto sourceRegisters = uop->getOperandRegisters();
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
    auto reg = sourceRegisters[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(reg, registerFile.get(reg));
    }
  }
}

std::tuple<bool, uint64_t> DecodeUnit::shouldFlush() const {
  return {shouldFlush_, pc};
}

} // namespace simeng
