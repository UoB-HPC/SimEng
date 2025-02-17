#pragma once

#include "simeng/branchpredictors/BranchPredictor.hh"

namespace simeng {

/** An "Always Not Taken" branch predictor; predicts all branches as not
 * taken. */
class AlwaysNotTakenPredictor : public BranchPredictor {
 public:
  /** Generate a branch prediction for the specified instruction address; will
   * always predict not taken. */
  BranchPrediction predict(uint64_t address, BranchType type,
                           int64_t knownOffset) override;

  /** Updates appropriate predictor model objects based on the address, type and
   * outcome of the branch instruction.  Update must be called on
   * branches in program order.  To check this, instructionId is also passed
   * to this function. */
  void update(uint64_t address, bool isTaken, uint64_t targetAddress,
              BranchType type, uint64_t instructionId) override;

  /** Provide flush logic for branch prediction scheme. As there's no flush
   * logic for an always taken predictor, this does nothing. */
  void flush(uint64_t address) override;

 private:
};

}  // namespace simeng
