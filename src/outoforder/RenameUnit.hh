#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "RegisterAllocationTable.hh"
#include "ReorderBuffer.hh"

namespace simeng {
namespace outoforder {

/** A rename unit for an out-of-order pipeline. Renames the input operands of
 * instructions, allocates registers for destination operands, and reserves
 * slots in the Reorder Buffer. */
class RenameUnit {
 public:
  /** Construct a rename unit with a reference to input/output buffers, the
   * reorder buffer, and the register allocation table. */
  RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
             PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
             ReorderBuffer& rob, RegisterAllocationTable& rat);

  /** Ticks this unit. Renames registers of instructions, and allocates ROB
   * space. */
  void tick();

 private:
  /** A buffer of instructions to rename. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;

  /** A buffer to write renamed instructions to. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchBuffer;

  /** The reorder buffer. */
  ReorderBuffer& reorderBuffer;

  /** The register allocation table. */
  RegisterAllocationTable& rat;
};

}  // namespace outoforder
}  // namespace simeng
