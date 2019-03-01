#include <memory>

#include "../MockBranchPredictor.hh"
#include "../MockInstruction.hh"
#include "inorder/DecodeUnit.hh"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace simeng {

using ::testing::Return;

// Tests that the decode unit output remains empty when an empty macro-op is
// present
TEST(InOrderDecodeUnit, TickEmpty) {
  auto input = PipelineBuffer<MacroOp>(1, {});
  auto output = PipelineBuffer<std::shared_ptr<Instruction>>(1, nullptr);
  auto registerFile = RegisterFile({1});
  MockBranchPredictor predictor;

  auto decodeUnit = inorder::DecodeUnit(input, output, registerFile, predictor);
  decodeUnit.tick();

  EXPECT_EQ(output.getTailSlots()[0], nullptr);
}

// Tests that the decode unit extracts an processes a uop correctly
TEST(InOrderDecodeUnit, Tick) {
  MockInstruction* uop = new MockInstruction();

  auto input = PipelineBuffer<MacroOp>(1, {});
  input.getHeadSlots()[0] = {std::shared_ptr<Instruction>(uop)};

  auto output = PipelineBuffer<std::shared_ptr<Instruction>>(1, nullptr);
  auto registerFile = RegisterFile({1});
  MockBranchPredictor predictor;

  EXPECT_CALL(*uop, checkEarlyBranchMisprediction())
      .WillOnce(Return(std::tuple<bool, uint64_t>(false, 0)));

  auto decodeUnit = inorder::DecodeUnit(input, output, registerFile, predictor);
  decodeUnit.tick();

  // Check result uop is the same as the one provided
  auto result = output.getTailSlots()[0];
  EXPECT_EQ(result.get(), uop);

  // Check no flush was requested
  EXPECT_EQ(decodeUnit.shouldFlush(), false);
}

// Tests that the decode unit requests a flush when a non-branch is mispredicted
TEST(InOrderDecodeUnit, Flush) {
  MockInstruction* uop = new MockInstruction();

  auto input = PipelineBuffer<MacroOp>(1, {});
  input.getHeadSlots()[0] = {std::shared_ptr<Instruction>(uop)};

  auto output = PipelineBuffer<std::shared_ptr<Instruction>>(1, nullptr);
  auto registerFile = RegisterFile({1});
  MockBranchPredictor predictor;

  EXPECT_CALL(*uop, checkEarlyBranchMisprediction())
      .WillOnce(Return(std::tuple<bool, uint64_t>(true, 1)));
  EXPECT_CALL(*uop, isBranch()).WillOnce(Return(false));
  EXPECT_CALL(*uop, getInstructionAddress()).WillOnce(Return(2));

  // Check the predictor is updated with the correct instruction address and PC
  EXPECT_CALL(predictor, update(2, false, 1));

  auto decodeUnit = inorder::DecodeUnit(input, output, registerFile, predictor);
  decodeUnit.tick();

  // Check that a flush was correctly requested
  EXPECT_EQ(decodeUnit.shouldFlush(), true);
  EXPECT_EQ(decodeUnit.getFlushAddress(), 1);
}

}  // namespace simeng
