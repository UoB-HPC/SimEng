#include "gtest/gtest.h"
#include "simeng/BTBPredictor.hh"

namespace {

// Tests that a BTBPredictor will predict not taken for an unencountered branch
TEST(BTBPredictorTest, Miss) {
  auto predictor = simeng::BTBPredictor(8);
  auto prediction = predictor.predict(0);
  EXPECT_FALSE(prediction.taken);
}

// Tests that a BTBPredictor will predict a previously encountered branch
// correctly, when no address aliasing has occurred
TEST(BTBPredictorTest, Hit) {
  auto predictor = simeng::BTBPredictor(8);
  predictor.update(0, true, 1);
  auto prediction = predictor.predict(0);
  EXPECT_TRUE(prediction.taken);
  EXPECT_EQ(prediction.target, 1);
}

// Tests that a BTBPredictor will predict not taken after a branch direction
// change
TEST(BTBPredictorTest, DirectionChange) {
  auto predictor = simeng::BTBPredictor(8);
  predictor.update(0, true, 1);
  predictor.update(0, false, 0);
  auto prediction = predictor.predict(0);
  EXPECT_FALSE(prediction.taken);
}

}  // namespace
