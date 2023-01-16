#include "gtest/gtest.h"
#include "simeng/pipeline/PipelineBuffer.hh"

namespace simeng {
namespace pipeline {

class PipelineBufferTest : public ::testing::TestWithParam<size_t> {};

// Test that we can create a pipeline buffer with a specified initial value
TEST_P(PipelineBufferTest, Create) {
  auto pipelineBuffer = PipelineBuffer<int>(GetParam(), 1);
  for (size_t i = 0; i < GetParam(); i++) {
    EXPECT_EQ(pipelineBuffer.getTailSlots()[i], 1);
    EXPECT_EQ(pipelineBuffer.getHeadSlots()[i], 1);
  }
}

// Test that values move when ticked
TEST_P(PipelineBufferTest, Tick) {
  auto pipelineBuffer = PipelineBuffer<int>(GetParam(), 0);
  for (size_t i = 0; i < GetParam(); i++) {
    pipelineBuffer.getTailSlots()[i] = i;
  }

  pipelineBuffer.tick();

  for (size_t i = 0; i < GetParam(); i++) {
    EXPECT_EQ(pipelineBuffer.getTailSlots()[i], 0);
    EXPECT_EQ(pipelineBuffer.getHeadSlots()[i], i);
  }
}

// Test that values don't move once stalled
TEST_P(PipelineBufferTest, Stall) {
  auto pipelineBuffer = PipelineBuffer<int>(GetParam(), 0);
  for (size_t i = 0; i < GetParam(); i++) {
    pipelineBuffer.getTailSlots()[i] = i;
  }

  pipelineBuffer.stall(true);
  EXPECT_TRUE(pipelineBuffer.isStalled());
  pipelineBuffer.tick();

  for (size_t i = 0; i < GetParam(); i++) {
    EXPECT_EQ(pipelineBuffer.getTailSlots()[i], i);
    EXPECT_EQ(pipelineBuffer.getHeadSlots()[i], 0);
  }
}

// Test that filling the buffer works
TEST_P(PipelineBufferTest, Fill) {
  auto pipelineBuffer = PipelineBuffer<int>(GetParam(), 1);

  pipelineBuffer.fill(0);

  for (size_t i = 0; i < GetParam(); i++) {
    EXPECT_EQ(pipelineBuffer.getTailSlots()[i], 0);
    EXPECT_EQ(pipelineBuffer.getHeadSlots()[i], 0);
  }
}

INSTANTIATE_TEST_SUITE_P(PipelineBufferTests, PipelineBufferTest,
                         ::testing::Range<size_t>(1, 9, 1));

}  // namespace pipeline
}  // namespace simeng
