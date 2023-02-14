#include "simeng/memory/SimpleMem.hh"

#include "gtest/gtest.h"

namespace {

TEST(SimpleMemTest, Read) {
  simeng::memory::SimpleMem* sMem = new simeng::memory::SimpleMem(100);
  char data[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  size_t dataSize = 10;
  uint64_t addr = 0;
  sMem->sendUntimedData(data, addr, dataSize);
  auto req = new simeng::memory::ReadPacket(addr, dataSize);
  auto res = (simeng::memory::ReadRespPacket*)sMem->requestAccess(req);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res->data[i], data[i]);
  }
  delete res;
  req = new simeng::memory::ReadPacket(8, 2);
  res = (simeng::memory::ReadRespPacket*)sMem->requestAccess(req);
  EXPECT_EQ(res->data[0], '8');
  EXPECT_EQ(res->data[1], '9');
  delete res;
  delete sMem;
}

TEST(SimpleMemTest, UntimedWrite) {
  simeng::memory::SimpleMem* sMem = new simeng::memory::SimpleMem(100);
  char data[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  size_t dataSize = 10;
  sMem->sendUntimedData(data, 0, dataSize);
  char* mem = sMem->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
  delete[] mem;
  delete sMem;
}

TEST(SimpleMemTest, Write) {
  simeng::memory::SimpleMem* sMem = new simeng::memory::SimpleMem(100);
  char data[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  size_t dataSize = 10;
  uint64_t addr = 0;
  auto res = sMem->requestAccess(
      new simeng::memory::WritePacket(addr, dataSize, data));
  char* mem = sMem->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
  delete[] mem;
  delete res;
  addr = 30;
  res =
      sMem->requestAccess(new simeng::memory::WritePacket(30, dataSize, data));
  mem = sMem->getUntimedData(30, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
  delete[] mem;
  delete res;
  delete sMem;
}

};  // namespace
