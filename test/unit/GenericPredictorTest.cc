#include "MockInstruction.hh"
#include "gtest/gtest.h"
#include "simeng/GenericPredictor.hh"

namespace simeng {

class GenericPredictorTest : public testing::Test {
 public:
  GenericPredictorTest() : uop(new MockInstruction), uopPtr(uop) {
    uop->setInstructionAddress(0);
  }

 protected:
  YAML::Node config = YAML::Load(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 10, RAS-entries: 5, Fallback-Static-Predictor: "
      "2}}");

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that a GenericPredictor will predict not taken for an unencountered
// branch
TEST_F(GenericPredictorTest, Miss) {
  auto predictor = simeng::GenericPredictor(config);
  auto prediction = predictor.predict(0, BranchType::Unconditional, 0);
  EXPECT_TRUE(prediction.taken);
}

// Tests that a GenericPredictor will predict a previously encountered branch
// correctly, when no address aliasing has occurred
TEST_F(GenericPredictorTest, Hit) {
  auto predictor = simeng::GenericPredictor(config);
  predictor.update(0, true, 1, BranchType::Unconditional);
  auto prediction = predictor.predict(0, BranchType::Unconditional, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 0);
}

// Tests that a GenericPredictor will predict not taken after 2 branch direction
// changes
TEST_F(GenericPredictorTest, DirectionChange) {
  auto predictor = simeng::GenericPredictor(config);
  predictor.update(0, true, 1, BranchType::Conditional);
  predictor.update(0, false, 0, BranchType::Conditional);
  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.taken);
}

}  // namespace simeng
