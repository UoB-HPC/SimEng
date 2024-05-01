#pragma once

#include <deque>
#include <map>
#include <vector>

#include "simeng/branchPredictors/BranchPredictor.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {

/** A Perceptron branch predictor implementing the branch predictor described in
 * Jimenez and Lin ("Dynamic branch prediction with perceptrons", IEEE High-
 * Performance Computer Architecture Symposium Proceedings (2001), 197-206 --
 * https://www.cs.utexas.edu/~lin/papers/hpca01.pdf).
 * The following predictors have been included:
 *
 * - Static predictor based on pre-allocated branch type.
 *
 * - A Branch Target Buffer (BTB) with a local and global indexing scheme and a
 * perceptron.
 *
 * - A Return Address Stack (RAS) is also in use.
 */

class PerceptronPredictor : public BranchPredictor {
 public:
  /** Initialise predictor models. */
  PerceptronPredictor(ryml::ConstNodeRef config = config::SimInfo::getConfig());
  ~PerceptronPredictor();

  /** Generate a branch prediction for the supplied instruction address, a
   * branch type, and a known branch offset; defaults to 0 meaning offset is not
   * known. Returns a branch direction and branch target address. */
  BranchPrediction predict(uint64_t address, BranchType type,
                           int64_t knownOffset = 0) override;

  /** Updates appropriate predictor model objects based on the address and
   * outcome of the branch instruction. */
  void update(uint64_t address, bool isTaken, uint64_t targetAddress,
              BranchType type) override;

  /** Provides RAS rewinding behaviour. */
  void flush(uint64_t address) override;

  /** Adds instruction to the Fetch Target Queue without making a new prediction
   */
  void addToFTQ(uint64_t address, bool isTaken) override;

 private:
  /** Returns the dot product of a perceptron and a history vector.  Used to
   * determine a direction prediction */
  int64_t getDotProduct(const std::vector<int8_t>& perceptron,
                        uint64_t history);

  /** The length in bits of the BTB index; BTB will have 2^bits entries. */
  uint64_t btbBits_;

  /** A 2^bits length vector of pairs containing a perceptron with
   * globalHistoryLength_ + 1 inputs, and a branch target.
   * The perceptrons are used to provide a branch direction prediction by
   * taking a dot product with the global history, as described
   * in Jiminez and Lin */
  std::vector<std::pair<std::vector<int8_t>, uint64_t>> btb_;

  /** Fetch Target Queue containing the direction prediction and previous global
   * history state of branches that are currently unresolved */
  std::deque<std::pair<bool, uint64_t>> ftq_;

  /** An n-bit history of previous branch directions where n is equal to
   * globalHistoryLength_.  Each bit represents a branch taken (1) or not
   * taken (0), with the most recent branch being the least-significant-bit */
  uint64_t globalHistory_ = 0;

  /** The number of previous branch directions recorded globally. */
  uint64_t globalHistoryLength_;

  /** A bit mask for truncating the global history to the correct size.
   * Stored as a member variable to avoid duplicative calculation */
  uint64_t globalHistoryMask_;

  /** The magnitude of the dot product of the perceptron and the global history,
   * below which the perceptron's weight must be updated */
  uint64_t trainingThreshold_;

  /** A return address stack. */
  std::deque<uint64_t> ras_;

  /** RAS history with instruction address as the keys. A non-zero value
   * represents the target prediction for a return instruction and a 0 entry for
   * a branch-and-link instruction. */
  std::map<uint64_t, uint64_t> rasHistory_;

  /** The size of the RAS. */
  uint64_t rasSize_;
};

}  // namespace simeng
