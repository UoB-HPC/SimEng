#include <array>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"
#include "simeng/memory/hierarchy/TagSchemes.hh"

using ::testing::_;
using ::testing::Property;
using ::testing::Return;

namespace {

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

class SetAssosciativeCacheTest : public testing::Test {
 public:
  SetAssosciativeCacheTest() { setup(); };

 protected:
  uint8_t assosciativity = 4;
  uint16_t clw = 4;
  uint32_t cacheSize = 4 * 1024;
  uint16_t hitLatency = 2;
  uint16_t accessLatency = 1;
  uint16_t missPenalty = 4;
  uint64_t memorySize = 1024 * 16;

  SimpleMem memory = SimpleMem(memorySize);
  SetAssosciativeCache cache = SetAssosciativeCache(
      clw, assosciativity, cacheSize, {hitLatency, accessLatency, missPenalty},
      std::make_unique<PIPT>(cacheSize, clw, assosciativity));

  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> freePort =
      std::make_shared<Port<std::unique_ptr<MemPacket>>>();

  std::vector<std::unique_ptr<MemPacket>> responses;
  PortMediator<std::unique_ptr<MemPacket>> cpuToCache;
  PortMediator<std::unique_ptr<MemPacket>> cacheToMem;

  // If there is a need for changing cache parameters, call the rebuild function
  // after having done so inside the test.
  void rebuild() {
    memory = SimpleMem(memorySize);
    cache = SetAssosciativeCache(
        clw, assosciativity, cacheSize,
        {hitLatency, accessLatency, missPenalty},
        std::make_unique<PIPT>(cacheSize, clw, assosciativity));
    cpuToCache = PortMediator<std::unique_ptr<MemPacket>>();
    cacheToMem = PortMediator<std::unique_ptr<MemPacket>>();
    freePort = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
    responses.clear();
    setup();
  }

 private:
  void setup() {
    memory = SimpleMem(memorySize);
    cache = SetAssosciativeCache(
        clw, assosciativity, cacheSize,
        {hitLatency, accessLatency, missPenalty},
        std::make_unique<PIPT>(cacheSize, clw, assosciativity));
    freePort->registerReceiver([&](std::unique_ptr<MemPacket> pkt) {
      responses.push_back(std::move(pkt));
    });

    auto memPort = memory.initPort();
    auto cacheTopPort = cache.initTopPort();
    auto cacheBottomPort = cache.initBottomPort();

    cpuToCache.connect(freePort, cacheTopPort);
    cacheToMem.connect(cacheBottomPort, memPort);
  }
};

TEST_F(SetAssosciativeCacheTest, CacheRebuild) {
  // This test is put here just to show how you can change cache parameters for
  // tests (if need be). The default configuration is as follows:
  // Memory size: 16KiB
  // Cache size: 4KiB
  // Cache line width: 4
  // Cache assosciativity: 4 Hit
  // latency: 2
  // Access latency: 1
  // Miss penalty: 4

  // To change any parameters modify the corresponding property inside the
  // SetAssosciativeCacheTest class and invoke the rebuild function.

  ASSERT_EQ(cache.getSize(), 4 * 1024);
  // CacheSize is a property of the SetAssosciativeCacheTest class
  cacheSize = 16 * 1024;
  // rebuild() function hasn't been called so actual size of cache is still 4KiB
  ASSERT_NE(cache.getSize(), cacheSize);
  // rebuild() function called, cache has now been configured with the new cache
  // size.
  rebuild();
  ASSERT_EQ(cache.getSize(), cacheSize);
}

TEST_F(SetAssosciativeCacheTest, CacheReadMiss) {
  memory.sendUntimedData({'5'}, 8, 1);
  auto req = MemPacket::createReadRequest(8, 1, 1);
  req->paddr_ = 8;

  freePort->send(std::move(req));
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 1);
  auto& resp = responses[0];
  EXPECT_TRUE(resp->isRead() && resp->isResponse());
  char a = resp->payload()[0];
  ASSERT_EQ(a, '5');
}

TEST_F(SetAssosciativeCacheTest, CacheReadHit) {
  memory.sendUntimedData({'4'}, 8, 1);
  auto req = MemPacket::createReadRequest(8, 1, 1);
  req->paddr_ = 8;
  freePort->send(std::move(req));

  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 1);
  auto& resp = responses[0];
  EXPECT_TRUE(resp->isRead() && resp->isResponse());
  char a = resp->payload()[0];
  ASSERT_EQ(a, '4');

  responses.clear();
  ASSERT_EQ(responses.size(), 0);

  auto req2 = MemPacket::createReadRequest(8, 1, 1);
  req2->paddr_ = 8;

  freePort->send(std::move(req2));

  cache.tick();
  cache.tick();
  cache.tick();

  ASSERT_EQ(responses.size(), 1);

  auto& resp2 = responses[0];
  EXPECT_TRUE(resp2->isRead() && resp2->isResponse());
  a = resp2->payload()[0];
  ASSERT_EQ(a, '4');
}

TEST_F(SetAssosciativeCacheTest, CacheWriteMissAndRead) {
  std::vector<char> dataVec = {'1', '2', '3', '4', '5', '6', '7', '8'};
  auto req = MemPacket::createWriteRequest(8, 8, 1, dataVec);
  req->paddr_ = 8;

  freePort->send(std::move(req));

  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 1);

  auto& resp = responses[0];
  EXPECT_TRUE(resp->isWrite() && resp->isResponse());

  responses.clear();

  req = MemPacket::createReadRequest(8, 8, 1);
  req->paddr_ = 8;

  freePort->send(std::move(req));

  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 1);

  auto& rresp = responses[0];
  EXPECT_TRUE(rresp->isRead() && rresp->isResponse());
  EXPECT_EQ(rresp->size_, 8);
  uint8_t ctr = 0;
  for (auto ch : rresp->payload()) {
    EXPECT_EQ(ch, dataVec[ctr]);
    ctr++;
  }
}

TEST_F(SetAssosciativeCacheTest, CapacityMiss) {
  std::array<uint64_t, 4> addrs = {0, 1024, 2048, 3072};
  for (auto addr : addrs) {
    auto req = MemPacket::createReadRequest(addr, 1, 1);
    req->paddr_ = addr;
    freePort->send(std::move(req));
  }
  // Since miss penalty is 4, hit latency is 2 and memory is SimpleMem, after 6
  // clock ticks all requests will be handled i.e on the 6th clock tick we
  // should have 4 responses.
  for (int x = 0; x < 6; x++) {
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
  }
  ASSERT_EQ(responses.size(), 4);

  // Given the initial addresses the entire set in the cache will be filled with
  // valid data. Accessing memory to the same set with a different tag will lead
  // to a capacity miss. We can verifying this by checking if it takes 4 ticks
  // for a new response to be generated. However, first we will verify a hit to
  // a previously accessed address to set a baseline.

  responses.clear();
  ASSERT_EQ(responses.size(), 0);

  auto req = MemPacket::createReadRequest(addrs[1], 1, 1);
  req->paddr_ = addrs[1];
  freePort->send(std::move(req));

  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 0);
  cache.tick();
  ASSERT_EQ(responses.size(), 1);

  // Now we cause a capacity miss by accessing addr 4096.
  responses.clear();
  ASSERT_EQ(responses.size(), 0);

  {
    auto req = MemPacket::createReadRequest(4096, 1, 1);
    req->paddr_ = 4096;
    freePort->send(std::move(req));

    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 1);
  }

  responses.clear();
  ASSERT_EQ(responses.size(), 0);
  // We now check if all all these previosly accessed addrs hit, especially the
  // one which caused a capacity miss
  {
    std::array<uint64_t, 4> addrs = {1024, 2048, 3072, 4096};
    for (int x = 0; x < 4; x++) {
      req = MemPacket::createReadRequest(addrs[x], 1, 1);
      req->paddr_ = addrs[x];
      freePort->send(std::move(req));
    }
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
    ASSERT_EQ(responses.size(), 4);
  }
}

TEST_F(SetAssosciativeCacheTest, MshrPrimaryFetch) {
  std::array<uint64_t, 4> addrs = {0, 1, 2, 3};
  for (auto addr : addrs) {
    auto req = MemPacket::createReadRequest(addr, 1, 1);
    req->paddr_ = addr;
    freePort->send(std::move(req));
  }

  // Tick two times to complete hit latency
  cache.tick();
  cache.tick();

  auto& mshrReg = cache.getMshr().getMshrReg(0, clw);
  ASSERT_EQ(mshrReg.clineIdx, 0);
  ASSERT_EQ(mshrReg.valid, 0);
  ASSERT_EQ(mshrReg.dirty, 0);
  ASSERT_EQ(mshrReg.entries.size(), 4);
  ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::PrimaryFetch);
  ASSERT_EQ(mshrReg.entries[1].type_, MshrEntry::Type::Secondary);
  ASSERT_EQ(mshrReg.entries[2].type_, MshrEntry::Type::Secondary);
  ASSERT_EQ(mshrReg.entries[3].type_, MshrEntry::Type::Secondary);
}

TEST_F(SetAssosciativeCacheTest, MshrPrimaryEviction) {
  // Write to invalid cache line causing a cache line fetch.
  std::array<uint64_t, 4> addrs = {0, 1024, 2048, 3072};
  int ctr = 0;
  for (auto addr : addrs) {
    char ch = 'a' + ctr;
    auto req =
        MemPacket::createWriteRequest(addr, 4, 1, std::vector<char>(4, ch));
    req->paddr_ = addr;
    freePort->send(std::move(req));
    ctr++;
  }

  // Tick two times to complete hit latency
  cache.tick();
  cache.tick();

  // Use the Mshr to check if a miss has happened. Here we also verify what kind
  // of miss has happened.
  ctr = 0;
  for (auto addr : addrs) {
    auto& mshrReg = cache.getMshr().getMshrReg(addr, clw);
    ASSERT_EQ(mshrReg.clineIdx, ctr);
    ASSERT_EQ(mshrReg.valid, 0);
    ASSERT_EQ(mshrReg.dirty, 0);
    ASSERT_EQ(mshrReg.entries.size(), 1);
    ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::PrimaryFetch);
    ctr++;
  }

  // Tick 4 times because miss penalty is 4 to resolve the primary fetch.
  for (int x = 0; x < 4; x++) {
    ASSERT_EQ(responses.size(), 0);
    cache.tick();
  }

  ASSERT_EQ(responses.size(), 4);
  responses.clear();

  // tag - index - offset - decimal
  // 0b100 - 00000000 - 00 - 4096
  // 0b101 - 00000000 - 00 - 5120
  // 0b110 - 00000000 - 00 - 6144
  // 0b111 - 00000000 - 00 - 7168

  // These addresses will be used to cause evictions to cache lines that we
  // previosuly wrote to.
  std::array<uint64_t, 4> evicAddrs = {4096, 5120, 6144, 7168};

  ctr = 0;
  for (auto addr : evicAddrs) {
    char writeCh = 'z' - ctr;
    auto req = MemPacket::createWriteRequest(addr, 4, 1,
                                             std::vector<char>(4, writeCh));
    req->paddr_ = addr;
    freePort->send(std::move(req));

    // Tick two times because hit latency is 2 clock cycles.
    cache.tick();
    cache.tick();

    auto& mshrReg = cache.getMshr().getMshrReg(addr, clw);
    ASSERT_EQ(mshrReg.valid, 1);
    ASSERT_EQ(mshrReg.dirty, 1);
    ASSERT_EQ(mshrReg.entries.size(), 1);
    ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::PrimaryEviction);

    // Tick 4 times because miss latency is 4 clock cycles.
    for (int x = 0; x < 4; x++) {
      ASSERT_EQ(responses.size(), 0);
      cache.tick();
    }

    ASSERT_EQ(responses.size(), 1);
    responses.clear();

    // Check if cache lines we're correctly evicted and whether correct data was
    // written to the correct physical address.
    char cmpCh = 'a' + ctr;
    auto memResp = memory.getUntimedData(addr - 4096, 4);
    for (auto ch : memResp) {
      ASSERT_EQ(ch, cmpCh);
    }

    // Access newly evicted cache line to check if hit takes place (It should)
    req = MemPacket::createReadRequest(addr, 4, 1);
    req->paddr_ = addr;
    freePort->send(std::move(req));

    // Tick 3 times because hit latency is 2 and access latency is 1
    for (int x = 0; x < 3; x++) {
      ASSERT_EQ(responses.size(), 0);
      cache.tick();
    }
    ASSERT_EQ(responses.size(), 1);

    // Check if the read response contains the correct data.
    auto payload = responses[0]->payload();
    for (auto ch : payload) {
      ASSERT_EQ(ch, writeCh);
    }
    ctr++;
    responses.clear();
  }
}

TEST_F(SetAssosciativeCacheTest, ReplacementOnCacheLineBeingFetched) {
  // Write to invalid cache line causing a cache line fetch.
  std::array<uint64_t, 4> addrs = {0, 1024, 2048, 3072};
  int ctr = 0;

  memory.sendUntimedData({'p', 'p', 'p', 'p'}, 4096, 4);

  for (auto addr : addrs) {
    char ch = 'a' + ctr;
    auto req =
        MemPacket::createWriteRequest(addr, 4, 1, std::vector<char>(4, ch));
    req->paddr_ = addr;
    freePort->send(std::move(req));
    ctr++;
  }

  {
    auto req = MemPacket::createReadRequest(4096, 4, 1);
    req->paddr_ = 4096;
    freePort->send(std::move(req));
  }

  // Tick two times to complete hit latency
  cache.tick();
  cache.tick();

  // Use the Mshr to check if a miss has happened. Here we also verify what
  // kind of miss has happened.
  ctr = 0;
  for (auto addr : addrs) {
    auto& mshrReg = cache.getMshr().getMshrReg(addr, clw);
    ASSERT_EQ(mshrReg.clineIdx, ctr);
    ASSERT_EQ(mshrReg.valid, 0);
    ASSERT_EQ(mshrReg.dirty, 0);
    ASSERT_EQ(mshrReg.entries.size(), 1);
    ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::PrimaryFetch);
    ctr++;
  }

  auto& mshrReg = cache.getMshr().getMshrReg(4096, clw);
  ASSERT_EQ(mshrReg.clineIdx, 0);
  ASSERT_EQ(mshrReg.valid, 0);
  ASSERT_EQ(mshrReg.dirty, 0);
  ASSERT_EQ(mshrReg.entries.size(), 1);
  ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::BusyFetch);

  for (int x = 0; x < 4; x++) {
    cache.tick();
  }

  ASSERT_EQ(responses.size(), 4);
  responses.clear();

  cache.tick();
  ASSERT_EQ(responses.size(), 1);

  auto payload = responses[0]->payload();
  for (auto ch : payload) {
    ASSERT_EQ(ch, 'p');
  }

  auto vec = memory.getUntimedData(0, 4);
  for (auto ch : vec) {
    ASSERT_EQ(ch, 'a');
  }
}

TEST_F(SetAssosciativeCacheTest, ReplacementOnCacheLineBeingEvicted) {
  // Write to invalid cache line causing a cache line fetch.
  std::array<uint64_t, 4> addrs = {0, 1024, 2048, 3072};
  int ctr = 0;
  for (auto addr : addrs) {
    char ch = 'a' + ctr;
    auto req =
        MemPacket::createWriteRequest(addr, 4, 1, std::vector<char>(4, ch));
    req->paddr_ = addr;
    freePort->send(std::move(req));
    ctr++;
  }

  for (int x = 0; x < 6; x++) {
    cache.tick();
  }

  ctr = 0;
  addrs = {4096, 5120, 6144, 7168};
  for (auto addr : addrs) {
    char ch = 'z' - ctr;
    auto req =
        MemPacket::createWriteRequest(addr, 4, 1, std::vector<char>(4, ch));
    req->paddr_ = addr;
    freePort->send(std::move(req));
    ctr++;
  }

  cache.tick();
  cache.tick();

  // Use the Mshr to check if a miss has happened. Here we also verify what
  // kind of miss has happened.
  ctr = 0;
  for (auto addr : addrs) {
    auto& mshrReg = cache.getMshr().getMshrReg(addr, clw);
    ASSERT_EQ(mshrReg.clineIdx, ctr);
    ASSERT_EQ(mshrReg.valid, 1);
    ASSERT_EQ(mshrReg.dirty, 1);
    ASSERT_EQ(mshrReg.entries.size(), 1);
    ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::PrimaryEviction);
    ctr++;
  }

  {
    auto req =
        MemPacket::createWriteRequest(8192, 4, 1, std::vector<char>(4, 'q'));
    req->paddr_ = 8192;
    freePort->send(std::move(req));
    cache.tick();
    cache.tick();
  }

  auto& mshrReg = cache.getMshr().getMshrReg(8192, clw);
  ASSERT_EQ(mshrReg.clineIdx, 0);
  ASSERT_EQ(mshrReg.valid, 1);
  ASSERT_EQ(mshrReg.dirty, 1);
  ASSERT_EQ(mshrReg.entries.size(), 1);
  ASSERT_EQ(mshrReg.entries[0].type_, MshrEntry::Type::BusyEviction);

  for (int x = 0; x < 4; x++) {
    cache.tick();
  }

  auto payload = memory.getUntimedData(4096, 4);
  for (auto ch : payload) {
    ASSERT_EQ(ch, 'z');
  }

  cache.tick();
  responses.clear();

  {
    auto req = MemPacket::createReadRequest(8192, 4, 1);
    req->paddr_ = 8192;
    freePort->send(std::move(req));

    cache.tick();
    cache.tick();
    cache.tick();

    auto payload = responses[0]->payload();
    for (auto ch : payload) {
      ASSERT_EQ(ch, 'q');
    }
  }
}

}  // namespace
