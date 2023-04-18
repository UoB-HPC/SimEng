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
  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that a GenericPredictor will predict the correct direction on a
// miss
TEST_F(GenericPredictorTest, Miss) {
  simeng::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 10, RAS-entries: 5, Fallback-Static-Predictor: "
      "Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.taken);

  simeng::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 10, RAS-entries: 5, Fallback-Static-Predictor: "
      "Always-Not-Taken}}");
  predictor = simeng::GenericPredictor();
  prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.taken);
  prediction = predictor.predict(8, BranchType::Unconditional, 0);
  EXPECT_TRUE(prediction.taken);
}

// Tests that a GenericPredictor will predict branch-and-link return pairs
// correctly
TEST_F(GenericPredictorTest, RAS) {
  simeng::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 10, RAS-entries: 10, Fallback-Static-Predictor: "
      "Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  auto prediction = predictor.predict(8, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 16);
  prediction = predictor.predict(24, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 32);
  prediction = predictor.predict(40, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 48);
  prediction = predictor.predict(56, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 64);
  prediction = predictor.predict(72, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 80);

  prediction = predictor.predict(84, BranchType::Return, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 76);
  prediction = predictor.predict(68, BranchType::Return, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 60);
  prediction = predictor.predict(52, BranchType::Return, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 44);
  prediction = predictor.predict(36, BranchType::Return, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 28);
  prediction = predictor.predict(20, BranchType::Return, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 12);
}

// Tests that a GenericPredictor will predict a previously encountered branch
// correctly, when no address aliasing has occurred
TEST_F(GenericPredictorTest, Hit) {
  simeng::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 1, RAS-entries: 5, Fallback-Static-Predictor: "
      "Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.update(0, false, 16, BranchType::Conditional);

  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 16);
}

// Tests that a GenericPredictor will predict correctly for two different
// behaviours of the same branch but in different states of the program
TEST_F(GenericPredictorTest, GlobalIndexing) {
  simeng::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 5, RAS-entries: 5, Fallback-Static-Predictor: "
      "Always-Not-Taken}}");
  auto predictor = simeng::GenericPredictor();
  // Spool up first global history pattern
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0x1F, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.taken);
  EXPECT_EQ(prediction.target, 0x23);
  // Set entry in BTB
  predictor.update(0x1F, true, 0xAB, BranchType::Conditional);

  // Spool up second global history pattern
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  // Ensure default behaviour for re-encounter but with different global history
  prediction = predictor.predict(0x1F, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.taken);
  EXPECT_EQ(prediction.target, 0x23);
  // Set entry in BTB
  predictor.update(0x1F, true, 0xBA, BranchType::Conditional);

  // Recreate first global history pattern
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  // Get prediction
  prediction = predictor.predict(0x1F, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 0xAB);
  // Set entry in BTB
  predictor.update(0x1F, true, 0xAB, BranchType::Conditional);

  // Recreate second global history pattern
  predictor.update(0, false, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, true, 4, BranchType::Unconditional);
  predictor.update(0, false, 4, BranchType::Unconditional);
  // Get prediction
  prediction = predictor.predict(0x1F, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 0xBA);
  predictor.update(0x1F, true, 0xBA, BranchType::Conditional);
}

}  // namespace simeng
