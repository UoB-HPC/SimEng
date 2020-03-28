#include "gtest/gtest.h"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/VariableLatencyMemoryInterface.hh"

namespace {

// Test that we can write data and it completes after a number of cycles.
TEST(LatencyMemoryInterfaceTest, FixedWriteData) {
  // Create a memory interface with a two cycle latency
  uint32_t memoryData = 0;
  simeng::FixedLatencyMemoryInterface memory(
      reinterpret_cast<char*>(&memoryData), 4, 2);
  EXPECT_FALSE(memory.hasPendingRequests());

  // Write a 32-bit value to memory
  // Should ignore the 7 cycle latency and opt for the interface defined latency
  simeng::MemoryAccessTarget target = {0, 4, 0};
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

// Test that we can write data and it completes after a number of cycles.
TEST(LatencyMemoryInterfaceTest, VariableWriteData) {
  /* Create a memory interface with a two cycle integer latency 
   * and a three cycle floating-point latency */
  uint32_t memoryData = 0;
  simeng::VariableLatencyMemoryInterface memory(
      reinterpret_cast<char*>(&memoryData), 4, 2, 3);
  EXPECT_FALSE(memory.hasPendingRequests());

  // Write a 32-bit integer value to memory
  simeng::MemoryAccessTarget target = {0, 4, 0};
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

  // Write a 32-bit floating-point value to memory
  target = {0, 4, 1};
  value = 0x12345678;
  memory.requestWrite(target, value);
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick once - request should still be pending
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick again - request should still be pending
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick again - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());
  EXPECT_EQ(memoryData, 0x12345678);
}

}  // namespace
