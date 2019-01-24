#pragma once

#include "BranchPredictor.hh"

namespace simeng {

class AlwaysNotTakenPredictor : public BranchPredictor {
 public:
  BranchPrediction predict(uint64_t instructionAddress) override;
  void update(uint64_t instructionAddress, bool taken, uint64_t targetAddress) override;
};

} // namespace simeng
