#include "DecodeUnit.hh"

#include <iostream>
#include <cassert>

namespace simeng {

DecodeUnit::DecodeUnit(PipelineBuffer<MacroOp>& fromFetch, PipelineBuffer<std::shared_ptr<Instruction>>& toExecute, RegisterFile& registerFile) : fromFetchBuffer(fromFetch), toExecuteBuffer(toExecute), registerFile(registerFile) {};

void DecodeUnit::tick() {
  std::cout << "Decode: tick()" << std::endl;
  if (toExecuteBuffer.isStalled()) {
    fromFetchBuffer.stall(true);
    std::cout << "Decode: stalled" << std::endl;
    return;
  }

  fromFetchBuffer.stall(false);
  
  auto macroOp = fromFetchBuffer.getHeadSlots()[0];

  // Assume single uop per macro op for this version
  // TODO: Stall on multiple uops and siphon one per cycle, recording progress
  auto out = toExecuteBuffer.getTailSlots();

  if (macroOp.size() == 0) {
    std::cout << "Decode: nop" << std::endl;
    out[0] = nullptr;
  } else {
    out[0] = macroOp[0];
  }

  fromFetchBuffer.getHeadSlots()[0] = {};
}

void DecodeUnit::forwardOperands(std::vector<Register> registers, std::vector<RegisterValue> values) {
  std::cout << "Decode: forwarding" << std::endl;
  assert(registers.size() == values.size() && "Mismatched register and value vector sizes");

  auto uop = toExecuteBuffer.getTailSlots()[0];
  if (uop == nullptr) {
    std::cout << "Decode: forwarding was nop" << std::endl;
    return;
  }
  if (uop->canExecute()) {
    std::cout << "Decode: forwarding unnecessary" << std::endl;
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

} // namespace simeng
