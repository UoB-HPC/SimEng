#include "RenameUnit.hh"

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

  reorderBuffer.reserve(uop);

  toDispatchBuffer.getTailSlots()[0] = uop;
}
}  // namespace outoforder
}  // namespace simeng
