#include "MockInstruction.hh"
#include "gtest/gtest.h"
#include "simeng/branchpredictors/PerceptronPredictor.hh"

namespace simeng {

class PerceptronPredictorTest : public testing::Test {
 public:
  PerceptronPredictorTest() : uop(new MockInstruction), uopPtr(uop) {
    uop->setInstructionAddress(0);
  }

 protected:
  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

// Tests that the PerceptronPredictor will predict the correct direction on a
// miss
TEST_F(PerceptronPredictorTest, Miss) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 11, "
      "Global-History-Length: 10, RAS-entries: 5}}");
  auto predictor = simeng::PerceptronPredictor();
  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  prediction = predictor.predict(8, BranchType::Unconditional, 0);
  EXPECT_TRUE(prediction.isTaken);
}

// Tests that the PerceptronPredictor will predict branch-and-link return pairs
// correctly
TEST_F(PerceptronPredictorTest, RAS) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 11, "
      "Global-History-Length: 10, RAS-entries: 10}}");
  auto predictor = simeng::PerceptronPredictor();
  auto prediction = predictor.predict(8, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 16);
  prediction = predictor.predict(24, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 32);
  prediction = predictor.predict(40, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 48);
  prediction = predictor.predict(56, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 64);
  prediction = predictor.predict(72, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 80);

  prediction = predictor.predict(84, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 76);
  prediction = predictor.predict(68, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 60);
  prediction = predictor.predict(52, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 44);
  prediction = predictor.predict(36, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 28);
  prediction = predictor.predict(20, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 12);
}

// Tests that the PerceptronPredictor will predict a previously encountered
// branch correctly, when no address aliasing has occurred
TEST_F(PerceptronPredictorTest, Hit) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 5, "
      "Global-History-Length: 1, RAS-entries: 5}}");
  auto predictor = simeng::PerceptronPredictor();
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 0);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 1);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 2);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 3);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 4);

  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 16);
}

// Tests that the PeceptronPredictor will predict correctly for two different
// behaviours of the same branch but in different states of the program
TEST_F(PerceptronPredictorTest, GlobalIndexing) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 10, "
      "Global-History-Length: 10, RAS-entries: 5}}");
  auto predictor = simeng::PerceptronPredictor();
  // Spool up first global history pattern
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 0);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 1);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 2);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 3);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 4);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 5);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 6);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 7);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 8);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 9);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0);
  // Set entry in BTB
  predictor.update(0x7C, false, 0x80, BranchType::Conditional, 10);

  // Spool up second global history pattern
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 11);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 12);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 13);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 14);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 15);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 16);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 17);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 18);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 19);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 20);
  // Ensure default behaviour for re-encounter but with different global history
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional, 21);

  // Recreate first global history pattern
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 22);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 23);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 24);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 25);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 26);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 27);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 28);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 29);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 30);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 31);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x80);
  // Set entry in BTB
  predictor.update(0x7C, true, 0x80, BranchType::Conditional, 32);

  // Recreate second global history pattern
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 33);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 34);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 35);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 36);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 37);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 38);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 39);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 40);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 41);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, false, 4, BranchType::Conditional, 42);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xBA);
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional, 43);
}

// Test Flush of RAS functionality
TEST_F(PerceptronPredictorTest, flush) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 11, "
      "Global-History-Length: 10, RAS-entries: 10}}");
  auto predictor = simeng::PerceptronPredictor();
  // Add some entries to the RAS
  auto prediction = predictor.predict(8, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 16);
  prediction = predictor.predict(24, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 32);
  prediction = predictor.predict(40, BranchType::SubroutineCall, 8);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 48);

  // Start getting entries from RAS
  prediction = predictor.predict(52, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 44);
  prediction = predictor.predict(36, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 28);

  // Flush address
  predictor.flush(36);

  // Continue getting entries from RAS
  prediction = predictor.predict(20, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 28);
  prediction = predictor.predict(16, BranchType::Return, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 12);
}

// Test that update correctly corrects the speculatively updated gloabl history
TEST_F(PerceptronPredictorTest, speculativeGlobalHistory) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Perceptron, BTB-Tag-Bits: 2, "
      "Global-History-Length: 6, RAS-entries: 5}}");
  auto predictor = simeng::PerceptronPredictor();
  // spool up a global history to set the target address
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 0);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 1);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 2);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 3);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 4);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 5);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0xFF, BranchType::Conditional, 0);
  // Defaults to not-taken
  EXPECT_FALSE(prediction.isTaken);
  // Should predict target of address + 4
  EXPECT_EQ(prediction.target, 0x103);
  // Set entry in BTB
  predictor.update(0xFF, true, 0xAB, BranchType::Conditional, 6);

  // recreate this global history but with incorrect predictions
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 7);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 8);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 9);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 10);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 11);
  predictor.predict(0, BranchType::Conditional, 0, true);
  predictor.update(0, true, 4, BranchType::Conditional, 12);
  // Ensure prediction is correct with new target address
  prediction = predictor.predict(0xFF, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xAB);
  // Set entry in BTB
  predictor.update(0xFF, true, 0xAB, BranchType::Conditional, 13);
}

}  // namespace simeng
