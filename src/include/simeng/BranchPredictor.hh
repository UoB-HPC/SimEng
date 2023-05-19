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
  bool taken;

  /** The branch instruction's target address. If `taken = false`, the value
   * will be ignored. */
  uint64_t target;

  /** Check for equality of two branch predictions . */
  bool operator==(const BranchPrediction& other) {
    if ((taken == other.taken) && (target == other.target))
      return true;
    else
      return false;
  }

  /** Check for inequality of two branch predictions . */
  bool operator!=(const BranchPrediction& other) {
    if ((taken != other.taken) || (target != other.target))
      return true;
    else
      return false;
  }
};

/** An abstract branch predictor interface. */
class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  /** Generate a branch prediction for the specified instruction address with a
   * branch type and possible known branch offset. */
  virtual BranchPrediction predict(uint64_t address, BranchType type,
                                   int64_t knownOffset) = 0;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. */
  virtual void update(uint64_t address, bool taken, uint64_t targetAddress,
                      BranchType type) = 0;

  /** Provides flushing behaviour for the implemented branch prediction schemes
   * via the instruction address.
   */
  virtual void flush(uint64_t address) = 0;
};

}  // namespace simeng