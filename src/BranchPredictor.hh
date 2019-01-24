#pragma once

#include <cstdint>
#include <tuple>

namespace simeng {

struct BranchPrediction {
  bool taken;
  uint64_t target;
};

class BranchPredictor {
 public:
  virtual ~BranchPredictor(){};

  virtual BranchPrediction predict(uint64_t instructionAddress) = 0;
  virtual void update(uint64_t instructionAddress, bool taken, uint64_t targetAddress) = 0;
};

} // namespace simeng
