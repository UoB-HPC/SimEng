#pragma once

#include <deque>

#include "../Instruction.hh"
#include "LoadStoreQueue.hh"
#include "RegisterAliasTable.hh"

namespace simeng {
namespace outoforder {

/** A Reorder Buffer (ROB) implementation. Contains an in-order queue of
 * in-flight instructions. */
class ReorderBuffer {
 public:
  /** Constructs a reorder buffer of maximum size `maxSize`, supplying a
   * reference to the register alias table. */
  ReorderBuffer(unsigned int maxSize, RegisterAliasTable& rat,
                LoadStoreQueue& lsq);

  /** Add the provided instruction to the ROB. */
  void reserve(std::shared_ptr<Instruction> insn);

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

 private:
  /** A reference to the register alias table. */
  RegisterAliasTable& rat;

  /** A reference to the load/store queue. */
  LoadStoreQueue& lsq;

  /** The maximum size of the ROB. */
  unsigned int maxSize;

  /** The buffer containing in-flight instructions. */
  std::deque<std::shared_ptr<Instruction>> buffer;

  /** Whether the core should be flushed after the most recent commit. */
  bool shouldFlush_ = false;

  /** The target instruction address the PC should be reset to after the most
   * recent commit.
   */
  uint64_t pc;

  /** The sequence ID of the youngest instruction that should remain after the
   * current flush. */
  uint64_t flushAfter;

  /** The next available sequence ID. */
  uint64_t seqId = 0;
};

}  // namespace outoforder
}  // namespace simeng
