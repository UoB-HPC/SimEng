#pragma once

#include "simeng/BranchPredictor.hh"

namespace simeng {

/** An "Always Not Taken" branch predictor; predicts all branches as not taken.
 */
class AlwaysNotTakenPredictor : public BranchPredictor {
 public:
  /** Generate a branch prediction for the specified instruction address; will
   * always predict not taken. */
  BranchPrediction predict(std::shared_ptr<Instruction>& uop) override;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. As this model is static, this does nothing. */
  void update(std::shared_ptr<Instruction>& uop, bool taken,
              uint64_t targetAddress) override;
};

}  // namespace simeng
