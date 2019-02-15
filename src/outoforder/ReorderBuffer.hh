#pragma once

#include <deque>

#include "../Instruction.hh"
#include "RegisterAliasTable.hh"

namespace simeng {
namespace outoforder {

/** A Reorder Buffer (ROB) implementation. Contains an in-order queue of
 * in-flight instructions. */
class ReorderBuffer {
 public:
  /** Constructs a reorder buffer of maximum size `maxSize`, supplying a
   * reference to the register alias table. */
  ReorderBuffer(unsigned int maxSize, RegisterAliasTable& rat);

  /** Add the provided instruction to the ROB. */
  void reserve(std::shared_ptr<Instruction> insn);

  /** Commit and remove up to `maxCommitSize` instructions. */
  unsigned int commit(unsigned int maxCommitSize);

  /** Flush all instructions with a sequence ID greater than `afterSeqId`. */
  void flush(uint64_t afterSeqId);

  /** Retrieve the current size of the ROB. */
  unsigned int size() const;

 private:
  /** A reference to the register alias table. */
  RegisterAliasTable& rat;
  /** The maximum size of the ROB. */
  unsigned int maxSize;

  /** The buffer containing in-flight instructions. */
  std::deque<std::shared_ptr<Instruction>> buffer;

  /** The next available sequence ID. */
  uint64_t seqId = 0;
};

}  // namespace outoforder
}  // namespace simeng
