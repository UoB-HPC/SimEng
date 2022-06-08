#pragma once

#include <cstdint>
#include <tuple>

#include "simeng/Instruction.hh"

namespace simeng {

/** An abstract branch predictor interface. */
class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  /** Generate a branch prediction for the specified instruction address. */
  virtual BranchPrediction predict(std::shared_ptr<Instruction>& uop) = 0;

  /** Provide branch results to update the prediction model for the specified
   * instruction address. */
  virtual void update(std::shared_ptr<Instruction>& uop, bool taken,
                      uint64_t targetAddress) = 0;
};

}  // namespace simeng