#include "MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MMU.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;
using ::testing::ReturnRef;

namespace {

// Test that we can write data and it completes after a number of cycles.
TEST(FixedLatencyMemoryTest, WriteData) {
  // Create a memory interface with a two cycle latency
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::FixedLatencyMemory>(4, 2);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(fn);

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
  mmu->requestWrite(target, value);
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick once - request should still be pending
  mem->tick();
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick again - request should have completed
  mem->tick();
  EXPECT_FALSE(mmu->hasPendingRequests());

  auto resp = mem->getUntimedData(0, 4);

  uint32_t castedValue = 0;
  memcpy(&castedValue, resp.data(), 4);
  EXPECT_EQ(castedValue, 0xDEADBEEF);
}

TEST(FixedLatencyMemoryTest, UntimedWriteData) {
  // Create a memory interface with a two cycle latency
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::FixedLatencyMemory>(4, 2);

  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  mem->sendUntimedData(data, 0, dataSize);
  auto payload = mem->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(payload[i], data[i]);
  }
}

// Test that we can write data and it completes after a number of cycles.
TEST(FixedLatencyMemoryTest, ReadData) {
  // Create a memory interface with a two cycle latency
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::FixedLatencyMemory>(4, 2);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(fn);

  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = mmu->initPort();
  auto port2 = mem->initPort();
  connection.connect(port1, port2);

  EXPECT_FALSE(mmu->hasPendingRequests());

  // Write a 32-bit value to memory
  simeng::memory::MemoryAccessTarget target = {0, 4};
  simeng::RegisterValue value = (uint32_t)0xDEADBEEF;

  mmu->requestWrite(target, value);
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick once - request should still be pending
  mem->tick();
  EXPECT_TRUE(mmu->hasPendingRequests());

  // Tick again - request should have completed
  mem->tick();
  EXPECT_FALSE(mmu->hasPendingRequests());

  auto resp = mem->getUntimedData(0, 4);

  uint32_t castedValue = 0;
  memcpy(&castedValue, resp.data(), 4);
  EXPECT_EQ(castedValue, 0xDEADBEEF);
}

// Test that out-of-bounds memory reads are correctly handled.
TEST(FixedLatencyMemoryTest, UnMappedAddrRead) {
  std::shared_ptr<simeng::memory::Mem> mem =
      std::make_shared<simeng::memory::FixedLatencyMemory>(4, 1);

  VAddrTranslator fn = [](uint64_t addr, uint64_t pid) -> uint64_t {
    if (!(addr > 0 && addr < 4)) {
      return simeng::OS::masks::faults::pagetable::FAULT |
             simeng::OS::masks::faults::pagetable::DATA_ABORT;
    }
    return addr;
  };

  std::shared_ptr<simeng::memory::MMU> mmu =
      std::make_shared<simeng::memory::MMU>(fn);

  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = mmu->initPort();
  auto port2 = mem->initPort();
  connection.connect(port1, port2);

  // Create a target such that address + size will overflow
  std::vector<simeng::memory::MemoryAccessTarget> overflowTarget = {
      {UINT64_MAX, 4}};
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  uop->setSequenceId(1);
  uop->setInstructionId(1);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(false));
  ON_CALL(*uop, getGeneratedAddresses())
      .WillByDefault(ReturnRef(overflowTarget));
  EXPECT_CALL(*uop, supplyData(UINT64_MAX, simeng::RegisterValue())).Times(1);
  mmu->requestRead(uop);

  // Create a regular out-of-bounds target
  std::vector<simeng::memory::MemoryAccessTarget> target = {{0, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setSequenceId(2);
  uop2->setInstructionId(2);
  ON_CALL(*uop2, isLoadReserved()).WillByDefault(Return(false));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  EXPECT_CALL(*uop2, supplyData(0, simeng::RegisterValue())).Times(1);
  mmu->requestRead(uop2);

  // Tick once - request should have completed
  mem->tick();
  EXPECT_FALSE(mmu->hasPendingRequests());
}

}  // namespace
