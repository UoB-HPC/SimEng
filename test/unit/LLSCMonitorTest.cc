#include <memory>

#include "MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Config.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;
using ::testing::ReturnRef;

namespace {

// Default VADDR translation function.
VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
  return vaddr;
};

// Const size of 2 full cache lines
const uint16_t dataSize = 512;

// A simple LL/SC case.
TEST(LLSCTest, successfulLLSC) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 1);
  EXPECT_EQ(writeResp[0].successful, true);
  // Check write happened
  auto memResp = sMem.getUntimedData(8, 8);
  std::vector<uint8_t> memRespData = {0xEF, 0xBE, 0xAD, 0xDE,
                                      0x78, 0x56, 0x34, 0x12};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// A simple failing LL/SC case.
TEST(LLSCTest, failingLLSC) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{264, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 1);
  EXPECT_EQ(writeResp[0].successful, false);
  // Check write didn't happened
  auto memResp = sMem.getUntimedData(264, 8);
  std::vector<uint8_t> memRespData = {0x08, 0x09, 0x0A, 0x0B,
                                      0x0C, 0x0D, 0x0E, 0x0F};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Pass the LL/SC with an interleaved write to another address.
TEST(LLSCTest, nonAffectingWrite) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send write to different address to monitored cache line
  mmu.requestWrite({260, 8}, {0xFFFFFFFFFFFFFFFF, 8});
  // Check write happened
  auto memResp = sMem.getUntimedData(260, 8);
  std::vector<uint8_t> memRespData = {0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{8, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(2);
  uop2->setSequenceId(2);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 2);
  EXPECT_EQ(writeResp[0].successful, true);
  // Check write happened
  memResp = sMem.getUntimedData(8, 8);
  memRespData = {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Fail the LL/SC due to an aligned write closing the monitor.
TEST(LLSCTest, alignedWriteMonitorClose) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send an aligned write to same cache line as monitored cache line
  mmu.requestWrite({240, 8}, {0xFFFFFFFFFFFFFFFF, 8});
  // Check write happened
  auto memResp = sMem.getUntimedData(240, 8);
  std::vector<uint8_t> memRespData = {0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{8, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(2);
  uop2->setSequenceId(2);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 2);
  EXPECT_EQ(writeResp[0].successful, false);
  // Check write didn't happened
  memResp = sMem.getUntimedData(8, 8);
  memRespData = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Fail the LL/SC due to an unaligned write closing the monitor.
TEST(LLSCTest, unalignedWriteMonitorClose) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{264, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 264);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send an unaligned write to same cache line as monitored cache line
  mmu.requestWrite({254, 8}, {0xFFFFFFFFFFFFFFFF, 8});
  // Check write happened
  // Check write happened
  auto memResp = sMem.getUntimedData(254, 8);
  std::vector<uint8_t> memRespData = {0xFF, 0xFF, 0xFF, 0xFF,
                                      0xFF, 0xFF, 0xFF, 0xFF};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{264, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(2);
  uop2->setSequenceId(2);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 2);
  EXPECT_EQ(writeResp[0].successful, false);
  // Check write didn't happened
  memResp = sMem.getUntimedData(264, 8);
  memRespData = {0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Pass the LL/SC with the second of 2 valid monitors being the target monitor.
TEST(LLSCTest, replacedMonitorSuccess) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{264, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 264);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send packet to open 2nd monitor
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{32, 8}};
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);
  ON_CALL(*uop2, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestRead(uop2);
  // Check response
  readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 2);
  EXPECT_EQ(readResp[1].requestId, 1);
  EXPECT_EQ(readResp[1].target.vaddr, 32);
  EXPECT_EQ(readResp[1].target.size, 8);
  EXPECT_EQ(readResp[1].data.get<uint64_t>(), 0x2726252423222120);

  // Send packet to close 2nd monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target3 = {{32, 8}};
  std::shared_ptr<simeng::MockInstruction> uop3 =
      std::make_shared<simeng::MockInstruction>();
  uop3->setInstructionId(2);
  uop3->setSequenceId(2);
  ON_CALL(*uop3, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop3, getGeneratedAddresses()).WillByDefault(ReturnRef(target3));
  mmu.requestWrite(uop3, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 2);
  EXPECT_EQ(writeResp[0].successful, true);
  // Check write happened
  auto memResp = sMem.getUntimedData(32, 8);
  std::vector<uint8_t> memRespData = {0xEF, 0xBE, 0xAD, 0xDE,
                                      0x78, 0x56, 0x34, 0x12};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Fail the LL/SC with the first of 2 valid monitors being the target monitor.
TEST(LLSCTest, replacedMonitorFailure) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send packet to open 2nd monitor
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{264, 8}};
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);
  ON_CALL(*uop2, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestRead(uop2);
  // Check response
  readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 2);
  EXPECT_EQ(readResp[1].requestId, 1);
  EXPECT_EQ(readResp[1].target.vaddr, 264);
  EXPECT_EQ(readResp[1].target.size, 8);
  EXPECT_EQ(readResp[1].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Send packet to close 2nd monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target3 = {{8, 8}};
  std::shared_ptr<simeng::MockInstruction> uop3 =
      std::make_shared<simeng::MockInstruction>();
  uop3->setInstructionId(2);
  uop3->setSequenceId(2);
  ON_CALL(*uop3, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop3, getGeneratedAddresses()).WillByDefault(ReturnRef(target3));
  mmu.requestWrite(uop3, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 2);
  EXPECT_EQ(writeResp[0].successful, false);
  // Check write didn't happened
  auto memResp = sMem.getUntimedData(8, 8);
  std::vector<uint8_t> memRespData = {0x08, 0x09, 0x0A, 0x0B,
                                      0x0C, 0x0D, 0x0E, 0x0F};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

// Fail the LL/SC due to a context switch being performed between the load and
// store.
TEST(LLSCTest, contextSwitchFailure) {
  Config::set(DEFAULT_CONFIG);
  // Set-up the memory environment.
  std::vector<char> data;
  for (uint16_t i = 0; i < dataSize; i++) {
    data.push_back(i);
  }
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(dataSize);
  simeng::memory::MMU mmu = simeng::memory::MMU(fn);
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initPort();
  auto port2 = mmu.initPort();
  connection.connect(port1, port2);
  sMem.sendUntimedData(data, 0, dataSize);

  // Send packet to open monitor
  std::shared_ptr<simeng::MockInstruction> uop =
      std::make_shared<simeng::MockInstruction>();
  std::vector<simeng::memory::MemoryAccessTarget> target = {{8, 8}};
  uop->setInstructionId(0);
  uop->setSequenceId(0);
  ON_CALL(*uop, isLoadReserved()).WillByDefault(Return(true));
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));
  mmu.requestRead(uop);
  // Check response
  auto readResp = mmu.getCompletedReads();
  EXPECT_EQ(readResp.size(), 1);
  EXPECT_EQ(readResp[0].requestId, 0);
  EXPECT_EQ(readResp[0].target.vaddr, 8);
  EXPECT_EQ(readResp[0].target.size, 8);
  EXPECT_EQ(readResp[0].data.get<uint64_t>(), 0x0F0E0D0C0B0A0908);

  // Emulate context switch by changing TID held in MMU
  mmu.setTid(1);

  // Send packet to close monitor
  std::vector<simeng::RegisterValue> regVal = {{0x12345678DEADBEEF, 8}};
  std::vector<simeng::memory::MemoryAccessTarget> target2 = {{8, 8}};
  std::shared_ptr<simeng::MockInstruction> uop2 =
      std::make_shared<simeng::MockInstruction>();
  uop2->setInstructionId(1);
  uop2->setSequenceId(1);
  ON_CALL(*uop2, isStoreCond()).WillByDefault(Return(true));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(target2));
  mmu.requestWrite(uop2, regVal);
  // Inspect result
  auto writeResp = mmu.getCompletedCondStores();
  EXPECT_EQ(writeResp.size(), 1);
  EXPECT_EQ(writeResp[0].requestId, 1);
  EXPECT_EQ(writeResp[0].successful, false);
  // Check write happened
  auto memResp = sMem.getUntimedData(8, 8);
  std::vector<uint8_t> memRespData = {0x08, 0x09, 0x0A, 0x0B,
                                      0x0C, 0x0D, 0x0E, 0x0F};
  for (int i = 0; i < memResp.size(); i++) {
    EXPECT_EQ((uint8_t)memResp[i], memRespData[i]);
  }
}

}  // namespace