#pragma once

#include "gmock/gmock.h"
#include "simeng/branchpredictors/BranchPredictor.hh"

namespace simeng {

/** Mock implementation of the `BranchPredictor` interface. */
class MockBranchPredictor : public BranchPredictor {
 public:
  MOCK_METHOD3(predict, BranchPrediction(uint64_t address, BranchType type,
                                         int64_t knownTarget));
  MOCK_METHOD5(update,
               void(uint64_t address, bool taken, uint64_t targetAddress,
                    BranchType type, uint64_t instructionId));
  MOCK_METHOD1(flush, void(uint64_t address));
};

}  // namespace simeng
