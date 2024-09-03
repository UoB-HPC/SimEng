#include "MockInstruction.hh"
#include "gtest/gtest.h"
#include "simeng/branchpredictors/GenericPredictor.hh"

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

// Tests that a GenericPredictor will predict correctly for two different
// behaviours of the same branch but in different states of the program
TEST_F(GenericPredictorTest, GlobalIndexing) {
  simeng::config::SimInfo::addToConfig(
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 10, "
      "Saturating-Count-Bits: 2, Global-History-Length: 10, RAS-entries: 5, "
      "Fallback-Static-Predictor: Always-Not-Taken}}");
  auto predictor = simeng::GenericPredictor();
  // Spool up first global history pattern
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 0);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 1);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 2);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 3);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 4);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 5);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 6);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 7);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 8);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 9);
  // Ensure default behaviour for first encounter
  auto prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x80);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xAB, BranchType::Conditional, 10);

  // Spool up second global history pattern
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 11);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 12);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 13);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 14);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 15);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 16);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 17);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 18);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 19);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 20);
  // Ensure default behaviour for re-encounter but with different global history
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_FALSE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0x80);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional, 21);

  // Recreate first global history pattern
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 22);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 23);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 24);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 25);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 26);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 27);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 28);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 29);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 30);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 31);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xAB);
  // Set entry in BTB
  predictor.update(0x7C, true, 0xAB, BranchType::Conditional, 32);

  // Recreate second global history pattern
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 33);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 34);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 35);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 4, BranchType::Conditional, 36);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 4, BranchType::Conditional, 37);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 38);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 39);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 40);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, true, 16, BranchType::Conditional, 41);
  predictor.predict(0, BranchType::Conditional, 0);
  predictor.update(0, false, 16, BranchType::Conditional, 42);
  // Get prediction
  prediction = predictor.predict(0x7C, BranchType::Conditional, 0);
  EXPECT_TRUE(prediction.isTaken);
  EXPECT_EQ(prediction.target, 0xBA);
  predictor.update(0x7C, true, 0xBA, BranchType::Conditional, 43);
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
      "{Branch-Predictor: {Type: Generic, BTB-Tag-Bits: 6, "
      "Saturating-Count-Bits: 2, Global-History-Length: 6, RAS-entries: 10, "
      "Fallback-Static-Predictor: Always-Taken}}");
  auto predictor = simeng::GenericPredictor();
  BranchPrediction pred;

  // Set up the target prediction for btb entry 000111 to be 65536.  No other
  // target predictions will be set during this test, so we can confirm that
  // we are accessing this btb entry by on the basis of this target prediction
  pred = predictor.predict(28, BranchType::Conditional, 0);
  EXPECT_TRUE(pred.isTaken);  // Default behaviour is to predict taken
  EXPECT_EQ(pred.target, 0);  // Target prediction not yet set
  predictor.update(28, true, 65536, BranchType::Conditional, 0);

  // Set up a speculative global history of 111111 on the basis of predictions
  pred = predictor.predict(4, BranchType::Conditional, 0);  // GH = 000011
  EXPECT_TRUE(pred.isTaken);
  EXPECT_EQ(pred.target, 0);
  pred = predictor.predict(4, BranchType::Conditional, 0);  // GH = 000111
  EXPECT_TRUE(pred.isTaken);
  EXPECT_EQ(pred.target, 0);
  pred = predictor.predict(4, BranchType::Conditional, 0);  // GH = 001111
  EXPECT_TRUE(pred.isTaken);
  EXPECT_EQ(pred.target, 0);
  pred = predictor.predict(4, BranchType::Conditional, 0);  // GH = 011111
  EXPECT_TRUE(pred.isTaken);
  EXPECT_EQ(pred.target, 0);
  pred = predictor.predict(4, BranchType::Conditional, 0);  // GH = 111111
  EXPECT_TRUE(pred.isTaken);
  EXPECT_EQ(pred.target, 0);

  // Get prediction for address 224 to access btb entry 000111
  pred = predictor.predict(224, BranchType::Conditional, 0);  // GH = 111111
  // Confirm prediction target is 65536
  EXPECT_EQ(pred.target, 65536);
  EXPECT_TRUE(pred.isTaken);

  // Now correct the speculative global history using updates
  predictor.update(4, false, 8, BranchType::Conditional, 1);  // GH = 011111
  predictor.update(4, false, 8, BranchType::Conditional, 2);  // GH = 001111
  predictor.update(4, false, 8, BranchType::Conditional, 3);  // GH = 000111

  // Now a prediction for address 0 should access btb entry 000111
  pred = predictor.predict(0, BranchType::Conditional, 0);
  EXPECT_EQ(pred.target, 65536);
}

}  // namespace simeng
