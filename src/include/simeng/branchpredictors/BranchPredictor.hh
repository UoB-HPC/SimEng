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

  /** The branch instruction's target address. If `isTaken == false`, the value
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
   * known. Returns a branch direction and branch target address. */
  virtual BranchPrediction predict(uint64_t address, BranchType type,
                                   int64_t knownOffset) = 0;

  /** Updates appropriate predictor model objects based on the address, type and
   * outcome of the branch instruction.  Update must be called on
   * branches in program order.  To check this, instructionId is also passed
   * to this function. */
  virtual void update(uint64_t address, bool isTaken, uint64_t targetAddress,
                      BranchType type, uint64_t instructionId) = 0;

  /** Provides flushing behaviour for the implemented branch prediction schemes
   * via the instruction address.  Branches must be flushed in reverse
   * program order (though, if a block of n instructions is being flushed at
   * once, the exact order that the individual instructions within this block
   * are flushed does not matter so long as they are all flushed). */
  virtual void flush(uint64_t address) = 0;


  // This variable is used only in debug mode to prevent errors -- therefore
  // hide behind ifdef
#ifndef NDEBUG
  /** The Id of the last instruction that update was called on -- used to
   * ensure that update is called in program order. */
  uint64_t lastUpdatedInstructionId_ = 0;
#endif
};

}  // namespace simeng