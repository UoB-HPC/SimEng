#pragma once

#include <cstdint>

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

  /** The branch instruction's target address. If `isTaken == false`, the value
   * will be ignored. */
  uint64_t target;

  /** Check for equality of two branch predictions . */
  bool operator==(const BranchPrediction& other) {
    return ((isTaken == other.isTaken) && (target == other.target));
  }

  /** Check for inequality of two branch predictions . */
  bool operator!=(const BranchPrediction& other) {
    return ((isTaken != other.isTaken) || (target != other.target));
  }
};

}  // namespace simeng