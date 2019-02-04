#include "RenameUnit.hh"

#include <iostream>

namespace simeng {
namespace outoforder {

RenameUnit::RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
                       PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
                       ReorderBuffer& rob)
    : fromDecodeBuffer(fromDecode),
      toDispatchBuffer(toDispatch),
      reorderBuffer(rob) {}

void RenameUnit::tick() {
  auto uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    return;
  }

  auto sourceRegisters = uop->getOperandRegisters();

  reorderBuffer.reserve(uop);

  toDispatchBuffer.getTailSlots()[0] = uop;
  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}
}  // namespace outoforder
}  // namespace simeng
