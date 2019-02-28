#include "PipelineBuffer.hh"
#include "gtest/gtest.h"

namespace {

// Test that we can create a pipeline buffer with a specified initial value
TEST(PipelineBufferTest, Create) {
  auto pipelineBuffer = simeng::PipelineBuffer<int>(1, 1);
  EXPECT_EQ(pipelineBuffer.getTailSlots()[0], 1);
  EXPECT_EQ(pipelineBuffer.getHeadSlots()[0], 1);
}

// Test that values move when ticked
TEST(PipelineBufferTest, Tick) {
  auto pipelineBuffer = simeng::PipelineBuffer<int>(1, 0);
  pipelineBuffer.getTailSlots()[0] = 1;
  pipelineBuffer.tick();
  EXPECT_EQ(pipelineBuffer.getHeadSlots()[0], 1);
}

// Test that values don't move once stalled
TEST(PipelineBufferTest, Stall) {
  auto pipelineBuffer = simeng::PipelineBuffer<int>(1, 0);
  pipelineBuffer.getTailSlots()[0] = 1;

  pipelineBuffer.stall(true);
  EXPECT_TRUE(pipelineBuffer.isStalled());

  pipelineBuffer.tick();
  EXPECT_EQ(pipelineBuffer.getHeadSlots()[0], 0);
}

// Test that filling the buffer works
TEST(PipelineBufferTest, Fill) {
  auto pipelineBuffer = simeng::PipelineBuffer<int>(1, 1);

  pipelineBuffer.fill(0);
  EXPECT_EQ(pipelineBuffer.getTailSlots()[0], 0);
  EXPECT_EQ(pipelineBuffer.getHeadSlots()[0], 0);
}

}  // namespace
