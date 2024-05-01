#include "MockInstruction.hh"
#include "gtest/gtest.h"
#include "simeng/branchPredictors/GenericPredictor.hh"

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
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 11, "
      "Saturating-Count-Bits: 2, Global-History-Length: 10, RAS-entries: 5, "
      "Fallback-Static-Predictor: Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);

  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 11, "
      "Saturating-Count-Bits: 2, Global-History-Length: 10, RAS-entries: 5, "
      "Fallback-Static-Predictor: Always-Not-Taken}}");
  predictor = simeng::GenericPredictor();
  prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  prediction = predictor.predict(8, BranchType::Unconditional, 0);
  EXPECT_TRUE(prediction.isTaken);
}

// Tests that a GenericPredictor will predict branch-and-link return pairs
// correctly
TEST_F(GenericPredictorTest, RAS) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 11, "
      "Saturating-Count-Bits: 2, Global-History-Length: 10, RAS-entries: 10, "
      "Fallback-Static-Predictor: Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
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

// Tests that a GenericPredictor will predict a previously encountered branch
// correctly, when no address aliasing has occurred
TEST_F(GenericPredictorTest, Hit) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 5, "
      "Saturating-Count-Bits: 2, Global-History-Length: 1, RAS-entries: 5, "
      "Fallback-Static-Predictor: Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional);

  auto prediction = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 16);
}

// Tests that a GenericPredictor will predict correctly for two different
// behaviours of the same branch but in different states of the program
TEST_F(GenericPredictorTest, GlobalIndexing) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 10, "
      "Saturating-Count-Bits: 2, Global-History-Length: 10, RAS-entries: 5, "
      "Fallback-Static-Predictor: Always-Not-Taken}}");
  auto predictor = simeng::GenericPredictor();
  // Spool up first global history pattern
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x80);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xAB, BranchType::Conditional);

  // Spool up second global history pattern
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  // Ensure default behaviour for re-encounter but with different global history
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x80);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional);

  // Recreate first global history pattern
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xAB);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xAB, BranchType::Conditional);

  // Recreate second global history pattern
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 16, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, false, 16, BranchType::Conditional);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xBA);
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional);
}

// Test Flush of RAS functionality
TEST_F(GenericPredictorTest, flush) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, "
      "Global-History-Length: 10, RAS-entries: 10, Fallback-Static-Predictor: "
      "Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
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

// Test that update correctly corrects the speculatively updated global history
TEST_F(GenericPredictorTest, speculativeGlobalHistory) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {BTB-Tag-Bits: 2, Saturating-Count-Bits: 6, "
      "Global-History-Length: 6, RAS-entries: 10, Fallback-Static-Predictor: "
      "Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  // spool up a global history to set the target address
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, true);
  predictor.update(0, true, 4, BranchType::Conditional);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0xFF, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x4);
  // Set entry in BTB
  predictor.update(0xFF, true, 0xAB, BranchType::Conditional);

  // recreate this global history but with incorrect predictions
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  predictor.addToFTQ(0, false);
  predictor.update(0, true, 4, BranchType::Conditional);
  // Ensure default behaviour for first encounter
  prediction = predictor.predict(0xFF, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xAB);
  // Set entry in BTB
  predictor.update(0xFF, true, 0xAB, BranchType::Conditional);
}

}  // namespace simeng
