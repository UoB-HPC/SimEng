#include "simeng/memory/SimpleMem.hh"

#include <cstdint>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"
#include "simeng/memory/MemPacket.hh"

using ::testing::_;
using ::testing::Property;
using ::testing::Return;

namespace {

/** A simple class used to recieve responses from memory. */
class SimpleMemTest : public testing::Test {
 public:
  /***/
  SimpleMemTest() { setup(); }
  /***/
  void setup() {
    // All tests operate on a cache line width of 1 byte
    simeng::memory::MemoryHierarchyPacket::clw = 1;
    dataPortMediator =
        simeng::PortMediator<simeng::memory::MemoryHierarchyPacket>();
    instrPortMediator = simeng::PortMediator<simeng::memory::CPUMemoryPacket>();
    memory = std::make_unique<simeng::memory::SimpleMem>(100);
    initPort();
    initInstrPort();
    auto dport = memory->initPort();
    auto iport = memory->initUntimedInstrReadPort();

    dataPortMediator.connect(port, dport);
    instrPortMediator.connect(instrPort, iport);
  };
  /** Function used to initialise the Data Port used
   * for bidirection communication. */
  std::shared_ptr<simeng::Port<simeng::memory::MemoryHierarchyPacket>>
  initPort() {
    port =
        std::make_shared<simeng::Port<simeng::memory::MemoryHierarchyPacket>>();
    auto fn = [this](simeng::memory::MemoryHierarchyPacket packet) -> void {
      resp = packet;
      return;
    };
    port->registerReceiver(fn);
    return port;
  }

  /** Function used to initialise the instruction Port used for bidirection
   * communication. */
  std::shared_ptr<simeng::Port<simeng::memory::CPUMemoryPacket>>
  initInstrPort() {
    instrPort =
        std::make_shared<simeng::Port<simeng::memory::CPUMemoryPacket>>();
    auto fn = [this](simeng::memory::CPUMemoryPacket packet) -> void {
      instrResp = packet;
      return;
    };
    instrPort->registerReceiver(fn);
    return instrPort;
  }

  std::unique_ptr<simeng::memory::SimpleMem> memory = nullptr;

  /* Holds the most recent response recieved through the port. */
  simeng::memory::MemoryHierarchyPacket resp;

  /* Holds the most recent response instruction read recieved through the
   * instruction port. */
  simeng::memory::CPUMemoryPacket instrResp;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<simeng::Port<simeng::memory::MemoryHierarchyPacket>> port =
      nullptr;
  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<simeng::Port<simeng::memory::CPUMemoryPacket>> instrPort =
      nullptr;

  simeng::PortMediator<simeng::memory::MemoryHierarchyPacket> dataPortMediator;
  simeng::PortMediator<simeng::memory::CPUMemoryPacket> instrPortMediator;
};

TEST_F(SimpleMemTest, Read) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  memory->sendUntimedData(data, addr, dataSize);
  auto req = simeng::memory::MemoryHierarchyPacket(
      simeng::memory::MemoryAccessType::READ, 0, 0, 10, 0, 0);
  port->send(req);
  auto res = resp.payload_;
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res[i], data[i]);
  }

  addr = 8;
  dataSize = 2;
  auto req2 = simeng::memory::MemoryHierarchyPacket(
      simeng::memory::MemoryAccessType::READ, addr, addr, dataSize, 0, 0);
  port->send(req2);
  auto res2 = resp.payload_;
  EXPECT_EQ(res2[0], '8');
  EXPECT_EQ(res2[1], '9');
}

TEST_F(SimpleMemTest, UntimedWrite) {
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(100);
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  sMem.sendUntimedData(data, 0, dataSize);
  auto mem = sMem.getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

TEST_F(SimpleMemTest, Write) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  auto req = simeng::memory::MemoryHierarchyPacket(
      simeng::memory::MemoryAccessType::WRITE, addr, addr, dataSize, 0, 0);
  req.clineAddr_ = addr;
  req.payload_ = data;
  port->send(req);
  auto mem = memory->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }

  addr = 30;
  auto req2 = simeng::memory::MemoryHierarchyPacket(
      simeng::memory::MemoryAccessType::WRITE, addr, addr, dataSize, 0, 0);
  req2.clineAddr_ = addr;
  port->send(req2);
  mem = memory->getUntimedData(addr, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

};  // namespace
