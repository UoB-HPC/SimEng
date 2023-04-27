#pragma once

#include <deque>
#include <functional>
#include <unordered_map>

#include "simeng/Instruction.hh"
#include "simeng/pipeline/LoadStoreQueue.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

/** A pipeline unit concerned with the tracking of issued instructions in
 * program-order. This tracking is used to facilitate the staging of
 * instructions at the writeback stage. Such staging is the delay of an
 * instruction's writeback to ensure that it is carried out in program-order.
 * Subsequently, the updates to the architectural state held within simulation
 * is updated in-order. */
class InOrderStager {
 public:
  /** The constructor of the unit. */
  InOrderStager();

  /** A function to record the issuing of instructions by a passed unique
   * sequence ID. */
  void recordIssue(uint64_t seqId);

  /** A function to query whether an instruction can writeback based on its
   * unique sequence ID being the youngest in program-order recorded by the
   * unit. */
  bool canWriteback(uint64_t seqId) const;

  /** A function to supply the next instruction sequence ID which can be
   * retired. */
  uint64_t getNextId() const;

  /** A function to record and release an instruction sequence ID from the unit
   * due to its retirement from the pipeline. */
  void recordRetired(uint64_t seqId);

  /** A function to remove IDs from the issueOrderBuffer_ which are older than
   * the passed ID the pipeline is being flushed from. */
  void flush(uint64_t afterSeqId);

  /** A function to clear the issueOrderBuffer_ due to a pipeline flush. */
  void flush();

  /** A function to query whether there are any entries in the
   * issueOrderBuffer_. */
  bool isEmpty() const;

 private:
  /** A queue to hold all in–flight issued instructions in a program-order. */
  std::deque<uint64_t> issueOrderQueue_;
};

}  // namespace pipeline
}  // namespace simeng
