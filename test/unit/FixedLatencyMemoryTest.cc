#include <cstdint>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MMU.hh"

class FixedLatencyMemoryTest : public testing::Test {
 public:
  FixedLatencyMemoryTest() { setup(2); };
  /** Function used to initialise members used for all tests. */
  void setup(uint64_t latency) {
    // All tests operate on a cache line width of 1 byte
    simeng::memory::MemoryHierarchyPacket::clw = 1;
    dataPortMediator = simeng::PortMediator<simeng::memory::CPUMemoryPacket>();
    instrPortMediator = simeng::PortMediator<simeng::memory::CPUMemoryPacket>();
    memory = simeng::memory::FixedLatencyMemory::build(false, 100, latency);
    initPort();
    initInstrPort();
    auto dport = memory->initDirectAccessDataPort();
    auto iport = memory->initUntimedInstrReadPort();

    dataPortMediator = simeng::PortMediator<simeng::memory::CPUMemoryPacket>();
    instrPortMediator = simeng::PortMediator<simeng::memory::CPUMemoryPacket>();

    dataPortMediator.connect(port, dport);
    instrPortMediator.connect(instrPort, iport);
  };

  /** Function which calls setup with a new latency. */
  void buildWithNewLatency(uint64_t latency) { setup(latency); }

  /** Function used to initialise the Data Port used
   * for bidirection communication. */
  std::shared_ptr<simeng::Port<simeng::memory::CPUMemoryPacket>> initPort() {
    port = std::make_shared<simeng::Port<simeng::memory::CPUMemoryPacket>>();
    auto fn = [this](simeng::memory::CPUMemoryPacket packet) -> void {
      dataResponses.push_back(packet);
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
      instrResponses.push_back(packet);
      return;
    };
    instrPort->registerReceiver(fn);
    return instrPort;
  }

  simeng::memory::CPUMemoryPacket createWriteRequest(
      uint64_t addr, uint16_t size, std::vector<char> payload) {
    simeng::memory::CPUMemoryPacket pkt(simeng::memory::MemoryAccessType::WRITE,
                                        addr, addr, size, 0, 0, 0);
    pkt.payload_ = payload;
    return pkt;
  };

  simeng::memory::CPUMemoryPacket createReadRequest(uint64_t addr,
                                                    uint16_t size) {
    return simeng::memory::CPUMemoryPacket(
        simeng::memory::MemoryAccessType::READ, addr, addr, size, 0, 0, 0);
  }

  /** Unique_ptr to FixedLatencyMemory. */
  std::shared_ptr<simeng::memory::FixedLatencyMemory> memory = nullptr;

  /** Vector to hold all data responses. */
  std::vector<simeng::memory::CPUMemoryPacket> dataResponses;

  /** Vector to hold all instruction responses. */
  std::vector<simeng::memory::CPUMemoryPacket> instrResponses;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<simeng::Port<simeng::memory::CPUMemoryPacket>> port = nullptr;

  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<simeng::Port<simeng::memory::CPUMemoryPacket>> instrPort =
      nullptr;

  /** Port mediator for the data port.  */
  simeng::PortMediator<simeng::memory::CPUMemoryPacket> dataPortMediator;

  /** Port mediator for the instruction port. */
  simeng::PortMediator<simeng::memory::CPUMemoryPacket> instrPortMediator;
};

namespace {
// Test that we can write data and it completes after a number of cycles.
TEST_F(FixedLatencyMemoryTest, Read) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  memory->sendUntimedData(data, addr, dataSize);
  auto req = createReadRequest(0, 10);
  port->send(req);

  ASSERT_EQ(dataResponses.size(), 0);
  memory->tick();
  memory->tick();
  ASSERT_EQ(dataResponses.size(), 1);

  auto res = dataResponses[0].payload_;
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res[i], data[i]);
  }

  dataResponses.clear();

  addr = 8;
  dataSize = 2;
  auto req2 = createReadRequest(addr, dataSize);
  port->send(req2);

  ASSERT_EQ(dataResponses.size(), 0);
  memory->tick();
  memory->tick();
  ASSERT_EQ(dataResponses.size(), 1);

  auto res2 = dataResponses[0].payload_;
  EXPECT_EQ(res2[0], '8');
  EXPECT_EQ(res2[1], '9');
}

TEST_F(FixedLatencyMemoryTest, InstructionRead) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  memory->sendUntimedData(data, addr, dataSize);
  auto req = createReadRequest(0, 10);
  ASSERT_EQ(instrResponses.size(), 0);
  instrPort->send(req);
  ASSERT_EQ(instrResponses.size(), 1);
  auto res = instrResponses[0].payload_;
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res[i], data[i]);
  }

  instrResponses.clear();

  addr = 8;
  dataSize = 2;
  auto req2 = createReadRequest(addr, dataSize);

  ASSERT_EQ(instrResponses.size(), 0);
  instrPort->send(req2);
  ASSERT_EQ(instrResponses.size(), 1);

  auto res2 = instrResponses[0].payload_;
  EXPECT_EQ(res2[0], '8');
  EXPECT_EQ(res2[1], '9');
}

TEST_F(FixedLatencyMemoryTest, UntimedWrite) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  memory->sendUntimedData(data, 0, dataSize);
  auto mem = memory->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

TEST_F(FixedLatencyMemoryTest, Write) {
  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  auto req = createWriteRequest(addr, dataSize, data);
  port->send(req);

  ASSERT_EQ(dataResponses.size(), 0);
  memory->tick();
  memory->tick();
  ASSERT_EQ(dataResponses.size(), 1);

  auto mem = memory->getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }

  dataResponses.clear();

  addr = 30;
  auto req2 = createWriteRequest(addr, dataSize, data);
  port->send(req2);

  ASSERT_EQ(dataResponses.size(), 0);
  memory->tick();
  memory->tick();
  ASSERT_EQ(dataResponses.size(), 1);

  mem = memory->getUntimedData(addr, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}
}  // namespace
