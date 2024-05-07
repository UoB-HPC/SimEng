#pragma once

#include <cassert>
#include <deque>
#include <map>
#include <vector>

#include "simeng/branchpredictors/BranchPredictor.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {

/** A generic branch predictor implementing well known/text book branch
 * predictor logic. The following predictors have been included:
 *
 * - Static predictor based on pre-allocated branch type.
 *
 * - A Branch Target Buffer (BTB) with a local and global indexing scheme and a
 * 2-bit saturating counter.
 *
 * - A Return Address Stack (RAS) is also in use.
 */

class GenericPredictor : public BranchPredictor {
 public:
  /** Initialise predictor models. */
  GenericPredictor(ryml::ConstNodeRef config = config::SimInfo::getConfig());
  ~GenericPredictor();

  /** Generate a branch prediction for the supplied instruction address, a
   * branch type, and a known branch offset; defaults to 0 meaning offset is not
   * known. Returns a branch direction and branch target address.  There is
   * also an optional boolean argument for whether or not the branch has
   * been identified as being a part of a loop.  If the branch is a loop
   * branch, then the fetch unit will reuse a previous prediction and so no
   * new prediction is required.  Therefore, predict() returns only a dummy
   * prediction. */
  BranchPrediction predict(uint64_t address, BranchType type,
                           int64_t knownOffset = 0,
                           bool isLoop = false) override;

  /** Updates appropriate predictor model objects based on the address, type and
   * outcome of the branch instruction.  Update must be called on branches in
   * program order. */
  void update(uint64_t address, bool isTaken, uint64_t targetAddress,
              BranchType type) override;

  /** Flushes the most recently predicted branch from the BP.  Address is
   * required to ensure that only the correct branch is removed from the RAS.
   * */
  void flush(uint64_t address) override;

 private:
  /** The bitlength of the BTB index; BTB will have 2^bits entries. */
  uint8_t btbBits_;

  /** A 2^bits length vector of pairs containing a satCntBits_-bit saturating
   * counter and a branch target. */
  std::vector<std::pair<uint8_t, uint64_t>> btb_;

  /** Fetch Target Queue containing the direction prediction and previous global
   * history state of branches that are currently unresolved */
  std::deque<std::pair<bool, uint64_t>> ftq_;

  /** Keep the last ftq entry as a separate variable to be reused for loops
   * in the event that the ftq_ is empty by the time the next predict() is
   * called */
  std::pair<bool, uint64_t> lastFtqEntry_;

  /** The number of bits used to form the saturating counter in a BTB entry. */
  uint8_t satCntBits_;

  /** An n-bit history of previous branch directions where n is equal to
   * globalHistoryLength_.  Each bit represents a branch taken (1) or not
   * taken (0), with the most recent branch being the least-significant-bit */
  uint64_t globalHistory_ = 0;

  /** The number of previous branch directions recorded globally. */
  uint16_t globalHistoryLength_;

  /** A bit mask for truncating the global history to the correct size.
   * Stored as a member variable to avoid duplicative calculation */
  uint64_t globalHistoryMask_;

  /** A return address stack. */
  std::deque<uint64_t> ras_;

  /** RAS history with instruction address as the keys. A non-zero value
   * represents the target prediction for a return instruction and a 0 entry for
   * a branch-and-link instruction. */
  std::map<uint64_t, uint64_t> rasHistory_;

  /** The size of the RAS. */
  uint16_t rasSize_;
};

}  // namespace simeng
