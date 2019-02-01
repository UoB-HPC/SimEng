#include "DispatchIssueUnit.hh"

namespace simeng {
namespace outoforder {

DispatchIssueUnit::DispatchIssueUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromRename,
    PipelineBuffer<std::shared_ptr<Instruction>>& toExecute,
    const RegisterFile& registerFile)
    : fromRenameBuffer(fromRename),
      toExecuteBuffer(toExecute),
      registerFile(registerFile){};

void DispatchIssueUnit::tick() {
  auto uop = fromRenameBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }

  toExecuteBuffer.getTailSlots()[0] = uop;
}

void DispatchIssueUnit::forwardOperands(
    const std::vector<Register>& registers,
    const std::vector<RegisterValue>& values) {
  assert(registers.size() == values.size() &&
         "Mismatched register and value vector sizes");

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

}  // namespace outoforder
}  // namespace simeng
