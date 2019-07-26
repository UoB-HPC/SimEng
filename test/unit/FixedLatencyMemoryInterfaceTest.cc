#include "gtest/gtest.h"
#include "simeng/FixedLatencyMemoryInterface.hh"

namespace {

// Test that we can write data and it completes after a number of cycles.
TEST(FixedLatencyMemoryInterfaceTest, WriteData) {
  // Create a memory interface with a two cycle latency
  uint32_t memoryData = 0;
  simeng::FixedLatencyMemoryInterface memory(
      reinterpret_cast<char*>(&memoryData), 4, 2);
  EXPECT_FALSE(memory.hasPendingRequests());

  // Write a 32-bit value to memory
  simeng::MemoryAccessTarget target = {0, 4};
  simeng::RegisterValue value = (uint32_t)0xDEADBEEF;
  memory.requestWrite(target, value);
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick once - request should still be pending
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick again - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());
  EXPECT_EQ(memoryData, 0xDEADBEEF);
}

}  // namespace
