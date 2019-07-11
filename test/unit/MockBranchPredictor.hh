#pragma once

#include "gmock/gmock.h"
#include "simeng/BranchPredictor.hh"

namespace simeng {

/** Mock implementation of the `BranchPredictor` interface. */
class MockBranchPredictor : public BranchPredictor {
 public:
  MOCK_METHOD1(predict, BranchPrediction(uint64_t instructionAddress));
  MOCK_METHOD3(update, void(uint64_t instructionAddress, bool taken,
                            uint64_t targetAddress));
};

}  // namespace simeng
