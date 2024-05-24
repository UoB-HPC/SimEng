#pragma once

#include <cstdint>
#include <tuple>

namespace simeng {

/** The types of branches recognised. */
enum class BranchType {
  Conditional = 0,
  LoopClosing,
  Return,
  SubroutineCall,
  Unconditional,
  Unknown
};

/** A branch result prediction for an instruction. */
struct BranchPrediction {
  /** Whether the branch will be taken. */
  bool isTaken;

  /** The branch instruction's target address. If `isTaken = false`, the value
   * will be ignored. */
  uint64_t target;

  /** Check for equality of two branch predictions . */
  bool operator==(const BranchPrediction& other) {
    if ((isTaken == other.isTaken) && (target == other.target))
      return true;
    else
      return false;
  }

  /** Check for inequality of two branch predictions . */
  bool operator!=(const BranchPrediction& other) {
    if ((isTaken != other.isTaken) || (target != other.target))
      return true;
    else
      return false;
  }
};

/** An abstract branch predictor interface. */
class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  /** Generate a branch prediction for the supplied instruction address, a
   * branch type, and a known branch offset; defaults to 0 meaning offset is not
   * known. Returns a branch direction and branch target address.  There is
   * also an optional boolean argument for whether or not the branch has
   * been identified as being a part of a loop.  If the branch is a loop
   * branch, then the fetch unit will reuse a previous prediction and so no
   * new prediction is required.  Therefore, predict() returns only a dummy
   * prediction. */
  virtual BranchPrediction predict(uint64_t address, BranchType type,
                                   int64_t knownOffset,
                                   bool isLoop = false) = 0;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. Update must be called on instructions in program
   * order. */
  virtual void update(uint64_t address, bool isTaken, uint64_t targetAddress,
                      BranchType type) = 0;

  /** Provides flushing behaviour for the implemented branch prediction schemes
   * via the instruction address.  Branches must be flushed in reverse
   * program order (though, if a block of n instructions is being flushed at
   * once, the exact order that the individual instructions within this block
   * are flushed does not matter so long as they are all flushed). */
  virtual void flush(uint64_t address) = 0;
};

}  // namespace simeng