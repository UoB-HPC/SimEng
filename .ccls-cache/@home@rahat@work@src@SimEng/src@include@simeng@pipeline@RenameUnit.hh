#pragma once

#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/PipelineBuffer.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"
#include "simeng/pipeline/ReorderBuffer.hh"

namespace simeng {
namespace pipeline {

/** A rename unit for an out-of-order pipelined processor. Renames the input
 * operands of instructions, allocates registers for destination operands, and
 * reserves slots in the Reorder Buffer. */
class RenameUnit {
 public:
  /** Construct a rename unit with a reference to input/output buffers, the
   * reorder buffer, and the register alias table. */
  RenameUnit(PipelineBuffer<std::shared_ptr<Instruction>>& input,
             PipelineBuffer<std::shared_ptr<Instruction>>& output,
             ReorderBuffer& rob, RegisterAliasTable& rat, LoadStoreQueue& lsq,
             uint16_t registerTypes);

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
  PipelineBuffer<std::shared_ptr<Instruction>>& input_;

  /** A buffer to write renamed instructions to. */
  PipelineBuffer<std::shared_ptr<Instruction>>& output_;

  /** The reorder buffer. */
  ReorderBuffer& reorderBuffer_;

  /** The register alias table. */
  RegisterAliasTable& rat_;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq_;

  /** A table recording the numbers of free physical registers for each register
   * file. */
  std::vector<uint16_t> freeRegistersAvailable_;

  /** The number of cycles stalled due to inability to allocate enough
   * destination registers. */
  uint64_t allocationStalls_ = 0;

  /** The number of cycles stalled due to insufficient ROB space. */
  uint64_t robStalls_ = 0;

  /** The number of cycles stalled due to insufficient load/store queue space
   * for a load operation. */
  uint64_t lqStalls_ = 0;

  /** The number of cycles stalled due to insufficient load/store queue space
   * for a store operation. */
  uint64_t sqStalls_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
