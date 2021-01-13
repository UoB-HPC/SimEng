#include "MockInstruction.hh"
#include "gtest/gtest.h"
#include "simeng/BTBPredictor.hh"

namespace simeng {

class BTBPredictorTest : public testing::Test {
 public:
  BTBPredictorTest() : uop(new MockInstruction), uopPtr(uop) {
    uop->setInstructionAddress(0);
  }

 protected:
  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that a BTBPredictor will predict not taken for an unencountered branch
TEST_F(BTBPredictorTest, Miss) {
  auto predictor = simeng::BTBPredictor(8);
  auto prediction = predictor.predict(uopPtr);
  EXPECT_FALSE(prediction.taken);
}

// Tests that a BTBPredictor will predict a previously encountered branch
// correctly, when no address aliasing has occurred
TEST_F(BTBPredictorTest, Hit) {
  auto predictor = simeng::BTBPredictor(8);
  predictor.update(uopPtr, true, 1);
  auto prediction = predictor.predict(uopPtr);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 1);
}

// Tests that a BTBPredictor will predict not taken after a branch direction
// change
TEST_F(BTBPredictorTest, DirectionChange) {
  auto predictor = simeng::BTBPredictor(8);
  predictor.update(uopPtr, true, 1);
  predictor.update(uopPtr, false, 0);
  auto prediction = predictor.predict(uopPtr);
  EXPECT_FALSE(prediction.taken);
}

}  // namespace simeng
