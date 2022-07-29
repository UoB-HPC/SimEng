#include <memory>

#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/pipeline/DecodeUnit.hh"

namespace simeng {
namespace pipeline {

using ::testing::_;
using ::testing::Property;
using ::testing::Return;

class PipelineDecodeUnitTest : public testing::Test {
 public:
  PipelineDecodeUnitTest()
      : input(1, {}),
        output(1, nullptr),
        stats("./stats-dump.txt"),
        registerFileSet({{8, 1}}),
        decodeUnit(input, output, predictor, stats),
        uop(new MockInstruction),
        uopPtr(uop),
        sourceRegisters({{0, 0}}) {}

 protected:
  PipelineBuffer<MacroOp> input;
  PipelineBuffer<std::shared_ptr<Instruction>> output;
  Statistics stats;
  RegisterFileSet registerFileSet;
  MockBranchPredictor predictor;
  DecodeUnit decodeUnit;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;

  std::vector<Register> sourceRegisters;
};

// Tests that the decode unit output remains empty when an empty macro-op is
// present
TEST_F(PipelineDecodeUnitTest, TickEmpty) {
  decodeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0], nullptr);
}

// Tests that the decode unit extracts an processes a uop correctly
TEST_F(PipelineDecodeUnitTest, Tick) {
  input.getHeadSlots()[0] = {uopPtr};

  EXPECT_CALL(*uop, checkEarlyBranchMisprediction())
      .WillOnce(Return(std::tuple<bool, uint64_t>(false, 0)));

  decodeUnit.tick();

  // Check result uop is the same as the one provided
  auto result = output.getTailSlots()[0];
  EXPECT_EQ(result.get(), uop);

  // Check no flush was requested
  EXPECT_EQ(decodeUnit.shouldFlush(), false);
}

// Tests that the decode unit requests a flush when a non-branch is mispredicted
TEST_F(PipelineDecodeUnitTest, Flush) {
  input.getHeadSlots()[0] = {uopPtr};

  uop->setInstructionAddress(2);

  // Return branch type as unconditional by default
  ON_CALL(*uop, getBranchType())
      .WillByDefault(Return(BranchType::Unconditional));

  EXPECT_CALL(*uop, checkEarlyBranchMisprediction())
      .WillOnce(Return(std::tuple<bool, uint64_t>(true, 1)));
  EXPECT_CALL(*uop, isBranch()).WillOnce(Return(false));

  // Check the predictor is updated with the correct instruction address and PC
  EXPECT_CALL(predictor, update(2, false, 1, BranchType::Unconditional));

  decodeUnit.tick();

  // Check that a flush was correctly requested
  EXPECT_EQ(decodeUnit.shouldFlush(), true);
  EXPECT_EQ(decodeUnit.getFlushAddress(), 1);
}

}  // namespace pipeline
}  // namespace simeng
