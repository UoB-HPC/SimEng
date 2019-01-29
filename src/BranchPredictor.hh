#pragma once

#include <cstdint>
#include <tuple>

namespace simeng {

/** A branch result prediction for an instruction. */
struct BranchPrediction {
  /** Whether the branch will be taken. */
  bool taken;

  /** The branch instruction's target address. If `taken = false`, the value
   * will be ignored. */
  uint64_t target;
};

/** An abstract branch predictor interface. */
class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  /** Generate a branch prediction for the specified instruction address. */
  virtual BranchPrediction predict(uint64_t instructionAddress) = 0;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. */
  virtual void update(uint64_t instructionAddress, bool taken,
                      uint64_t targetAddress) = 0;
};

}  // namespace simeng
