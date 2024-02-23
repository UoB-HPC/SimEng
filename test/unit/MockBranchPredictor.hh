#pragma once

#include "gmock/gmock.h"
#include "simeng/BranchPredictor.hh"

namespace simeng {

/** Mock implementation of the `BranchPredictor` interface. */
class MockBranchPredictor : public BranchPredictor {
 public:
  MOCK_METHOD3(predict, BranchPrediction(uint64_t address, BranchType type,
                                         int64_t knownTarget));
  MOCK_METHOD4(update, void(uint64_t address, bool taken,
                            uint64_t targetAddress, BranchType type));
  MOCK_METHOD1(flush, void(uint64_t address));
  MOCK_METHOD1(addToFTQ, void(uint64_t address));
};

}  // namespace simeng
