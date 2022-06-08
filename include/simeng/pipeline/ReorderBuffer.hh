#pragma once

#include <deque>
#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

/** A Reorder Buffer (ROB) implementation. Contains an in-order queue of
 * in-flight instructions. */
class ReorderBuffer {
 public:
  /** Constructs a reorder buffer of maximum size `maxSize`, supplying a
   * reference to the register alias table. */
  ReorderBuffer(
      unsigned int maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
      std::function<void(const std::shared_ptr<Instruction>&)> raiseException);

  /** Add the provided instruction to the ROB. */
  void reserve(const std::shared_ptr<Instruction>& insn);

  void commitMicroOps(uint64_t insnId);

  /** Commit and remove up to `maxCommitSize` instructions. */
  unsigned int commit(unsigned int maxCommitSize);

  /** Flush all instructions with a sequence ID greater than `afterSeqId`. */
  void flush(uint64_t afterSeqId);

  /** Retrieve the current size of the ROB. */
  unsigned int size() const;

  /** Retrieve the current amount of free space in the ROB. */
  unsigned int getFreeSpace() const;

  /** Query whether a memory order violation was discovered in the most recent
   * cycle. */
  bool shouldFlush() const;

  /** Retrieve the instruction address associated with the most recently
   * discovered memory order violation. */
  uint64_t getFlushAddress() const;

  /** Retrieve the sequence ID associated with the most recently discovered
   * memory order violation. */
  uint64_t getFlushSeqId() const;

  /** Get the number of instructions the ROB has committed. */
  uint64_t getInstructionsCommittedCount() const;

  /** Get the number of speculated loads which violated load-store ordering. */
  uint64_t getViolatingLoadsCount() const;

 private:
  /** A reference to the register alias table. */
  RegisterAliasTable& rat_;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq_;

  /** The maximum size of the ROB. */
  unsigned int maxSize_;

  /** A function to call upon exception generation. */
  std::function<void(std::shared_ptr<Instruction>)> raiseException_;

  /** The buffer containing in-flight instructions. */
  std::deque<std::shared_ptr<Instruction>> buffer_;

  /** Whether the core should be flushed after the most recent commit. */
  bool shouldFlush_ = false;

  /** The target instruction address the PC should be reset to after the most
   * recent commit.
   */
  uint64_t pc_;

  /** The sequence ID of the youngest instruction that should remain after the
   * current flush. */
  uint64_t flushAfter_;

  /** The next available sequence ID. */
  uint64_t seqId_ = 0;

  /** The next available instruction ID. Used to identify in-order groups of
   * micro-operations. */
  uint64_t insnId_ = 0;

  /** The number of instructions committed. */
  uint64_t instructionsCommitted_ = 0;

  /** The number of speculatived loads which violated load-store ordering. */
  uint64_t loadViolations_ = 0;
};

}  // namespace pipeline
}  // namespace simeng
