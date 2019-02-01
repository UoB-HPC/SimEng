#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "ReorderBuffer.hh"

namespace simeng {
namespace outoforder {

class RenameUnit {
 public:
  RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
             PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
             ReorderBuffer& rob);

  void tick();

 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchBuffer;

  ReorderBuffer& reorderBuffer;
};

}  // namespace outoforder
}  // namespace simeng
