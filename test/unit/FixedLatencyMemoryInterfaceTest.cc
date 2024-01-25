#include "gtest/gtest.h"
#include "simeng/FixedLatencyMemoryInterface.hh"

namespace {

class FixedLatencyMemoryInterfaceTest : public testing::Test {
 public:
  FixedLatencyMemoryInterfaceTest()
      : memory(memoryData.data(), memorySize, latency) {}

 protected:
  static constexpr uint16_t memorySize = 4;
  const uint16_t latency = 2;
  std::array<char, memorySize> memoryData = {(char)0xFE, (char)0xCA, (char)0xBA,
                                             (char)0xAB};

  simeng::RegisterValue value = {0xDEADBEEF, 4};
  simeng::RegisterValue value_oversized = {0xDEADBEEFDEADBEEF, 8};
  simeng::MemoryAccessTarget target = {0, 4};
  simeng::MemoryAccessTarget target_OutOfBound1 = {1000, 4};
  simeng::MemoryAccessTarget target_OutOfBound2 = {0, 8};

  const std::string writeOverflowStr =
      "Attempted to write beyond memory limit.";

  simeng::FixedLatencyMemoryInterface memory;
};

// Test that we can read data and it completes after a number of cycles.
TEST_F(FixedLatencyMemoryInterfaceTest, FixedReadData) {
  // Read a 32-bit value
  memory.requestRead(target, 1);
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick once - request should still be pending
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick again - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());

  auto entries = memory.getCompletedReads();
  EXPECT_EQ(entries.size(), 1);
  EXPECT_EQ(entries[0].requestId, 1);
  EXPECT_EQ(entries[0].data, simeng::RegisterValue(0xABBACAFE, 4));
  EXPECT_EQ(entries[0].target, target);
}

// Test that we can write data and it completes after a number of cycles.
TEST_F(FixedLatencyMemoryInterfaceTest, FixedWriteData) {
  // Write a 32-bit value to memory
  memory.requestWrite(target, value);
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick once - request should still be pending
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick again - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());
  EXPECT_EQ(reinterpret_cast<uint32_t*>(memoryData.data())[0], 0xDEADBEEF);
}

// Test that out-of-bounds memory reads are correctly handled.
TEST_F(FixedLatencyMemoryInterfaceTest, OutofBoundsRead) {
  // Create a target such that address + size will overflow
  memory.requestRead(target_OutOfBound1, 1);

  // Create a regular out-of-bounds target
  memory.requestRead(target_OutOfBound2, 2);

  // Tick once - request shouldn't have completed
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick twice - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());

  auto entries = memory.getCompletedReads();
  EXPECT_EQ(entries.size(), 2);

  auto overflowResult = entries[0];
  EXPECT_EQ(overflowResult.requestId, 1);
  EXPECT_FALSE(overflowResult.data);
  EXPECT_EQ(overflowResult.target, target_OutOfBound1);

  overflowResult = entries[1];
  EXPECT_EQ(overflowResult.requestId, 2);
  EXPECT_FALSE(overflowResult.data);
  EXPECT_EQ(overflowResult.target, target_OutOfBound2);
}

// Test that out-of-bounds memory writes are correctly handled.
TEST_F(FixedLatencyMemoryInterfaceTest, OutofBoundsWrite_1) {
  // Create a target such that address + size will overflow
  memory.requestWrite(target_OutOfBound1, value);

  // Tick once - request shouldn't have completed
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick twice - simulation should have come to a stop
  ASSERT_DEATH(memory.tick(), writeOverflowStr);
}

// Test that out-of-bounds memory writes are correctly handled.
TEST_F(FixedLatencyMemoryInterfaceTest, OutofBoundsWrite_2) {
  // Create a regular out-of-bounds target
  memory.requestWrite(target_OutOfBound2, value_oversized);

  // Tick once - request shouldn't have completed
  memory.tick();
  EXPECT_TRUE(memory.hasPendingRequests());

  // Tick twice - simulation should have come to a stop
  ASSERT_DEATH(memory.tick(), writeOverflowStr);
}

}  // namespace
