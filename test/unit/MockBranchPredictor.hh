#pragma once

#include "gmock/gmock.h"
#include "simeng/BranchPredictor.hh"

namespace simeng {

/** Mock implementation of the `BranchPredictor` interface. */
class MockBranchPredictor : public BranchPredictor {
 public:
  MOCK_METHOD1(predict, BranchPrediction(std::shared_ptr<Instruction> uop));
  MOCK_METHOD3(update, void(std::shared_ptr<Instruction> uop, bool taken,
                            uint64_t targetAddress));
};

}  // namespace simeng
