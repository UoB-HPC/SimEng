#pragma once

#include "../Instruction.hh"
#include "../PipelineBuffer.hh"
#include "LoadStoreQueue.hh"
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
             ReorderBuffer& rob, RegisterAliasTable& rat, LoadStoreQueue& lsq,
             uint8_t registerTypes);

  /** Ticks this unit. Renames registers of instructions, and allocates ROB
   * space. */
  void tick();

  /** Retrieve the number of cycles this unit stalled due to an inability to
   * allocate enough destination registers. */
  uint64_t getAllocationStalls() const;

  /** Retrieve the number of cycles this unit stalled due to insufficient ROB
   * space. */
  uint64_t getROBStalls() const;

  /** Retrieve the number of cycles stalled due to insufficient load/store queue
   * space for a load operation. */
  uint64_t getLoadQueueStalls() const;

  /** Retrieve the number of cycles stalled due to insufficient load/store queue
   * space for a store operation. */
  uint64_t getStoreQueueStalls() const;

 private:
  /** A buffer of instructions to rename. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;

  /** A buffer to write renamed instructions to. */
  PipelineBuffer<std::shared_ptr<Instruction>>& toDispatchBuffer;

  /** The reorder buffer. */
  ReorderBuffer& reorderBuffer;

  /** The register alias table. */
  RegisterAliasTable& rat;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq;

  /** A table recording the numbers of each type of register needed to
   * successfully allocate destinations for an instruction. */
  std::vector<uint8_t> freeRegistersNeeded;

  /** The number of cycles stalled due to inability to allocate enough
   * destination registers. */
  uint64_t allocationStalls = 0;

  /** The number of cycles stalled due to insufficient ROB space. */
  uint64_t robStalls = 0;

  /** The number of cycles stalled due to insufficient load/store queue space
   * for a load operation. */
  uint64_t lqStalls = 0;

  /** The number of cycles stalled due to insufficient load/store queue space
   * for a store operation. */
  uint64_t sqStalls = 0;
};

}  // namespace outoforder
}  // namespace simeng
