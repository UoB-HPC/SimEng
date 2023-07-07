#include "simeng/memory/SimpleMem.hh"

#include <memory>

#include "gtest/gtest.h"

namespace {

/** A simple class used to recieve responses from memory. */
class testRecv {
 public:
  testRecv(){};

  /** Function used to initialise the Data Port used for bidirection
   * communication. */
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
  initPort() {
    port_ = std::make_shared<
        simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>();
    auto fn =
        [this](std::unique_ptr<simeng::memory::MemPacket> packet) -> void {
      this->resp = std::move(packet);
      return;
    };
    port_->registerReceiver(fn);
    return port_;
  }

  /* Holds the most recent response recieved through the port. */
  std::unique_ptr<simeng::memory::MemPacket> resp = nullptr;

 private:
  /** Data port used for communication with the memory hierarchy. */
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      port_ = nullptr;
};

TEST(SimpleMemTest, Read) {
  simeng::memory::SimpleMem sMem = simeng::memory::SimpleMem(100);
  testRecv respRecv = testRecv();
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initMemPort();
  auto port2 = respRecv.initPort();
  connection.connect(port1, port2);

  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  sMem.sendUntimedData(data, addr, dataSize);
  auto req = simeng::memory::MemPacket::createReadRequest(addr, dataSize, 0, 0);
  req->paddr_ = addr;
  port2->send(std::move(req));
  auto res = respRecv.resp->payload();
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(res[i], data[i]);
  }

  addr = 8;
  dataSize = 2;
  auto req2 =
      simeng::memory::MemPacket::createReadRequest(addr, dataSize, 1, 0);
  req2->paddr_ = addr;
  port2->send(std::move(req2));
  auto res2 = respRecv.resp->payload();
  EXPECT_EQ(res2[0], '8');
  EXPECT_EQ(res2[1], '9');
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
  testRecv respRecv = testRecv();
  auto connection =
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>();
  auto port1 = sMem.initMemPort();
  auto port2 = respRecv.initPort();
  connection.connect(port1, port2);

  std::vector<char> data = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
  uint8_t dataSize = 10;
  uint64_t addr = 0;
  auto req =
      simeng::memory::MemPacket::createWriteRequest(addr, dataSize, 0, 0, data);
  req->paddr_ = addr;
  port2->send(std::move(req));
  auto mem = sMem.getUntimedData(0, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }

  addr = 30;
  auto req2 =
      simeng::memory::MemPacket::createWriteRequest(addr, dataSize, 1, 0, data);
  req2->paddr_ = addr;
  port2->send(std::move(req2));
  mem = sMem.getUntimedData(addr, dataSize);
  for (size_t i = 0; i < dataSize; i++) {
    EXPECT_EQ(mem[i], data[i]);
  }
}

};  // namespace
