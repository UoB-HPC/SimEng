
#include "gtest/gtest.h"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"

namespace {

// Test that we can write data and it completes after a number of cycles.
TEST(LatencyMemoryInterfaceTest, FixedWriteData) {
  // Create a memory interface with a two cycle latency
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::SimpleMem>(4);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(mem, fn, 0);

  simeng::FixedLatencyMemoryInterface memory(mmu, 2, mem->getMemorySize());

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

  auto resp = (simeng::memory::ReadRespPacket*)mem->requestAccess(
      new simeng::memory::ReadPacket(0, 4));
  uint32_t castedValue = 0;
  memcpy(&castedValue, resp->data, 4);
  EXPECT_EQ(castedValue, 0xDEADBEEF);
}

// Test that out-of-bounds memory reads are correctly handled.
TEST(LatencyMemoryInterfaceTest, UnMappedAddrRead) {
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::SimpleMem>(4);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    if (!(addr > 0 && addr < 4)) {
      return simeng::kernel::masks::faults::pagetable::fault |
             simeng::kernel::masks::faults::pagetable::dataAbort;
    }
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(mem, fn, 0);

  simeng::FixedLatencyMemoryInterface memory(mmu, 1, mem->getMemorySize());

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
