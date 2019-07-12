#include "../MockArchitecture.hh"
#include "../MockBranchPredictor.hh"
#include "../MockMemoryInterface.hh"
#include "Instruction.hh"
#include "arch/Architecture.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pipeline/FetchUnit.hh"
#include "pipeline/PipelineBuffer.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace simeng {
namespace pipeline {

class PipelineFetchUnitTest : public testing::Test {
 public:
  PipelineFetchUnitTest()
      : output(1, {}),
        fetchBuffer({0, 16}, 0),
        completedReads(&fetchBuffer, 1),
        fetchUnit(output, memory, 1024, 0, 4, isa, predictor) {}

 protected:
  PipelineBuffer<MacroOp> output;
  MockMemoryInterface memory;
  MockArchitecture isa;
  MockBranchPredictor predictor;

  std::pair<MemoryAccessTarget, RegisterValue> fetchBuffer;
  span<std::pair<MemoryAccessTarget, RegisterValue>> completedReads;

  FetchUnit fetchUnit;
};

// Tests that ticking a fetch unit attempts to predict a branch, attempts to
// predecode from the correct program counter using the supplied prediction, and
// generates output correctly.
TEST_F(PipelineFetchUnitTest, Tick) {
  BranchPrediction prediction{true, 1};
  MacroOp macroOp = {nullptr};

  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));

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
TEST_F(PipelineFetchUnitTest, TickStalled) {
  output.stall(true);

  EXPECT_CALL(predictor, predict(_)).Times(0);
  EXPECT_CALL(isa, predecode(_, _, _, _, _)).Times(0);

  fetchUnit.tick();

  // Verify that nothing was pushed to the output
  EXPECT_EQ(output.getTailSlots()[0].size(), 0);
}

// Tests that the fetch unit will handle instructions that straddle fetch block
// boundaries by automatically requesting the next block of data.
TEST_F(PipelineFetchUnitTest, FetchUnaligned) {
  ON_CALL(isa, getMaxInstructionSize()).WillByDefault(Return(4));
  ON_CALL(memory, getCompletedReads()).WillByDefault(Return(completedReads));

  // Set PC to 14, so there will not be enough data to start decoding
  EXPECT_CALL(isa, predecode(_, _, _, _, _)).Times(0);
  fetchUnit.updatePC(14);
  fetchUnit.tick();

  // Expect a block starting at address 16 to be requested when we fetch again
  EXPECT_CALL(memory, requestRead(Field(&MemoryAccessTarget::address, 16)))
      .Times(1);
  fetchUnit.requestFromPC();

  // Tick again, expecting that decoding will now resume
  std::pair<MemoryAccessTarget, RegisterValue> nextBlockValue = {{16, 16}, 0};
  span<std::pair<MemoryAccessTarget, RegisterValue>> nextBlock = {
      &nextBlockValue, 1};
  EXPECT_CALL(memory, getCompletedReads()).WillOnce(Return(nextBlock));
  EXPECT_CALL(isa, predecode(_, _, _, _, _)).WillOnce(Return(4));
  fetchUnit.tick();
}

}  // namespace pipeline
}  // namespace simeng
