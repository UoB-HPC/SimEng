#include "gtest/gtest.h"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/Translator.hh"

namespace {

// Test that we can write data and it completes after a number of cycles.
TEST(LatencyMemoryInterfaceTest, FixedWriteData) {
  // Create instance of address translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  address_translator->add_mapping({0, 4}, {0, 4});

  // Create a memory interface with a two cycle latency
  uint32_t memoryData = 0;
  simeng::FixedLatencyMemoryInterface memory(
      reinterpret_cast<char*>(&memoryData), 4, 2, *address_translator);
  EXPECT_FALSE(memory.hasPendingRequests());

  // Write a 32-bit value to memory
  // Should ignore the 7 cycle latency and opt for the interface defined latency
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

// Test that out-of-bounds memory reads are correctly handled.
TEST(LatencyMemoryInterfaceTest, OutofBoundsRead) {
  // Create instance of address translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  uint32_t memoryData = 0;
  simeng::FixedLatencyMemoryInterface memory(
      reinterpret_cast<char*>(&memoryData), 4, 1, *address_translator);

  // Create a target such that address + size will overflow
  simeng::MemoryAccessTarget overflowTarget = {UINT64_MAX, 4};
  memory.requestRead(overflowTarget, 1);

  // Create a regular out-of-bounds target
  simeng::MemoryAccessTarget target = {0, 8};
  memory.requestRead(target, 2);

  // Tick once - request should have completed
  memory.tick();
  EXPECT_FALSE(memory.hasPendingRequests());

  auto entries = memory.getCompletedReads();
  EXPECT_EQ(entries.size(), 2);

  auto overflowResult = entries[0];
  EXPECT_EQ(overflowResult.requestId, 1);
  EXPECT_EQ(overflowResult.data, simeng::RegisterValue());
  EXPECT_EQ(overflowResult.target, overflowTarget);

  auto result = entries[1];
  EXPECT_EQ(result.requestId, 2);
  EXPECT_EQ(result.data, simeng::RegisterValue());
  EXPECT_EQ(result.target, target);
}

}  // namespace
