#include "../MockArchitecture.hh"
#include "../MockBranchPredictor.hh"
#include "Architecture.hh"
#include "Instruction.hh"
#include "PipelineBuffer.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "inorder/FetchUnit.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace simeng {

// Tests that ticking a fetch unit attempts to predict a branch, attempts to
// predecode from the correct program counter using the supplied prediction, and
// generates output correctly.
TEST(InOrderFetchUnitTest, Tick) {
  MockArchitecture isa;
  MockBranchPredictor predictor;
  BranchPrediction prediction{true, 1};
  MacroOp macroOp = {nullptr};

  auto output = simeng::PipelineBuffer<simeng::MacroOp>(1, {});
  auto fetchUnit =
      simeng::inorder::FetchUnit(output, nullptr, 1024, isa, predictor);

  EXPECT_CALL(predictor, predict(0)).WillOnce(Return(prediction));

  // Verify the prediction matches the one we provided
  // Set the output parameter to a 1-wide macro-op
  EXPECT_CALL(isa, predecode(_, _, 0,
                             AllOf(Field(&BranchPrediction::taken, true),
                                   Field(&BranchPrediction::target, 1)),
                             _))
      .WillOnce(DoAll(SetArgReferee<4>(macroOp), Return(1)));

  fetchUnit.tick();

  // Verify that the macro-op was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 1);
}

// Tests that ticking a fetch unit does nothing if the output has stalled
TEST(InOrderFetchUnitTest, TickStalled) {
  MockArchitecture isa;
  MockBranchPredictor predictor;

  auto output = simeng::PipelineBuffer<simeng::MacroOp>(1, {});
  auto fetchUnit =
      simeng::inorder::FetchUnit(output, nullptr, 1024, isa, predictor);

  output.stall(true);

  EXPECT_CALL(predictor, predict(_)).Times(0);
  EXPECT_CALL(isa, predecode(_, _, _, _, _)).Times(0);

  fetchUnit.tick();

  // Verify that nothing was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 0);
}

}  // namespace simeng
