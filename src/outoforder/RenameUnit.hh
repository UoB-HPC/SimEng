#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "RegisterAliasTable.hh"
#include "ReorderBuffer.hh"

namespace simeng {
namespace outoforder {

/** A rename unit for an out-of-order pipeline. Renames the input operands of
 * instructions, allocates registers for destination operands, and reserves
 * slots in the Reorder Buffer. */
class RenameUnit {
 public:
  /** Construct a rename unit with a reference to input/output buffers, the
   * reorder buffer, and the register alias table. */
  RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
             PipelineBuffer<std::shared_ptr<Instruction>>& toDispatch,
             ReorderBuffer& rob, RegisterAliasTable& rat,
             uint8_t registerTypes);

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

  /** The register alias table. */
  RegisterAliasTable& rat;

  /** A table recording the numbers of each type of register needed to
   * successfully allocate destinations for an instruction. */
  std::vector<uint8_t> freeRegistersNeeded;
};

}  // namespace outoforder
}  // namespace simeng
