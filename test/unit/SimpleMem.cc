#include "simeng/memory/SimpleMem.hh"

#include "gtest/gtest.h"

namespace {

TEST(SimpleMemTest, Read) {
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(100);
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  sMem.sendUntimedData(data, addr, dataSize);
  auto req = simeng::memory::DataPacket(addr, dataSize,
                                        simeng::memory::READ_REQUEST, 0);
  auto res = sMem.requestAccess(req);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res.data_[i], data[i]);
  }
  auto req2 = simeng::memory::DataPacket(8, 2, simeng::memory::READ_REQUEST, 0);
  auto res2 = sMem.requestAccess(req2);
  EXPECT_EQ(res2.data_[0], '8');
  EXPECT_EQ(res2.data_[1], '9');
}

TEST(SimpleMemTest, UntimedWrite) {
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(100);
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  sMem.sendUntimedData(data, 0, dataSize);
  auto mem = sMem.getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

TEST(SimpleMemTest, Write) {
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(100);
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  sMem.requestAccess(simeng::memory::DataPacket(
      addr, dataSize, simeng::memory::WRITE_REQUEST, 0, data));
  auto mem = sMem.getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
  addr = 30;
  sMem.requestAccess(simeng::memory::DataPacket(
      30, dataSize, simeng::memory::WRITE_REQUEST, 0, data));
  mem = sMem.getUntimedData(30, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

};  // namespace
