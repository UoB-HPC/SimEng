#pragma once

#include "BranchPredictor.hh"

#include <vector>

namespace simeng {

class StaticBTBPredictor : public BranchPredictor {
 public:
  StaticBTBPredictor(uint8_t bits);

  BranchPrediction predict(uint64_t instructionAddress) override;
  void update(uint64_t instructionAddress, bool taken, uint64_t targetAddress) override;
 private:
  uint8_t bits;
  std::vector<uint64_t> btb;
  std::vector<bool> hasValue;

  uint64_t hash(uint64_t instructionAddress);
};

} // namespace simeng
