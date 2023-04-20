#include "gtest/gtest.h"
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
      std::make_shared<simeng::memory::MMU>(2, fn);

  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = mmu->initPort();
  auto port2 = mem->initPort();
  connection.connect(port1, port2);

  EXPECT_FALSE(mmu->hasPendingRequests());

  // Write a 32-bit value to memory
  // Should ignore the 7 cycle latency and opt for the interface defined latency
  simeng::memory::MemoryAccessTarget target = {0, 4};
  simeng::RegisterValue value = (uint32_t)0xDEADBEEF;
  mmu->requestWrite(target, value, 0);
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick once - request should still be pending
  mmu->tick();
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick again - request should have completed
  mmu->tick();
  EXPECT_FALSE(mmu->hasPendingRequests());

  auto resp = mem->getUntimedData(0, 4);

  // auto resp = mem->requestAccess(std::make_unique<simeng::memory::MemPacket>(
  //     0, 4, simeng::memory::READ_REQUEST, 0));

  uint32_t castedValue = 0;
  memcpy(&castedValue, resp.data(), 4);
  EXPECT_EQ(castedValue, 0xDEADBEEF);
}

// Test that out-of-bounds memory reads are correctly handled.
TEST(LatencyMemoryInterfaceTest, UnMappedAddrRead) {
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::SimpleMem>(4);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    if (!(addr > 0 && addr < 4)) {
      return simeng::OS::masks::faults::pagetable::FAULT |
             simeng::OS::masks::faults::pagetable::DATA_ABORT;
    }
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(1, fn);

  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = mmu->initPort();
  auto port2 = mem->initPort();
  connection.connect(port1, port2);

  // Create a target such that address + size will overflow
  simeng::memory::MemoryAccessTarget overflowTarget = {UINT64_MAX, 4};
  mmu->requestRead(overflowTarget, 1);

  // Create a regular out-of-bounds target
  simeng::memory::MemoryAccessTarget target = {0, 8};
  mmu->requestRead(target, 2);

  // Tick once - request should have completed
  mmu->tick();
  EXPECT_FALSE(mmu->hasPendingRequests());

  auto entries = mmu->getCompletedReads();
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
