#pragma once

#include <gmock/gmock-matchers.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "EventBuilder.hh"
#include "simeng/Port.hh"
#include "simeng/memory/FixedLatencyMemory.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/memory/hierarchy/CacheImpl.hh"
#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

class CacheTestEngine;
struct Expectation;
struct ExpectationResult;

struct Event {
  static inline uint64_t idCounter = 0;
  const uint64_t id;

  Event() : id(idCounter++) {}
  virtual ~Event(){};

  virtual void doEvent(CacheTestEngine* engine, uint16_t index) = 0;
  virtual std::string serialise(uint16_t index) = 0;
};

struct UntimedReadEvent : public Event {
  uint64_t paddr;
  uint64_t size;
  Expectation* expectation = nullptr;

  UntimedReadEvent(uint64_t addr, uint64_t sz, Expectation* expec)
      : paddr(addr), size(sz), expectation(expec) {}

  void doEvent(CacheTestEngine* engine, uint16_t index) override;
  std::string serialise(uint16_t index) override;
};

struct UntimedWriteEvent : public Event {
  uint64_t paddr;
  uint64_t size;
  std::vector<char> data;

  UntimedWriteEvent(uint64_t addr, uint64_t sz, std::vector<char> dt)
      : paddr(addr), size(sz), data(dt) {}
  ~UntimedWriteEvent() {}

  void doEvent(CacheTestEngine* engine, uint16_t index) override;
  std::string serialise(uint16_t index) override;
};

struct MemoryRequestEvent : public Event {
  std::unique_ptr<simeng::memory::MemPacket> request;
  Expectation* expectation = nullptr;

  MemoryRequestEvent(std::unique_ptr<simeng::memory::MemPacket> packet,
                     Expectation* expec)
      : request(std::move(packet)), expectation(expec) {
    request->id_ = id;
  }

  void doEvent(CacheTestEngine* engine, uint16_t index) override;
  std::string serialise(uint16_t index) override;
};

struct TickEvent : public Event {
  uint16_t tickFor;
  TickEvent(uint16_t ticks) : tickFor(ticks) {}

  void doEvent(CacheTestEngine* engine, uint16_t index) override;
  std::string serialise(uint16_t index) override;
};

struct ExpectationResult {
  uint64_t endTick = 0;
  std::vector<char> resultPayload;
};

struct Expectation {
  uint64_t startTick = 0;
  uint64_t expectedTicks = 0;
  std::vector<char> expectedPayload;
  std::string message;

  virtual ~Expectation() {}

  virtual void expect(ExpectationResult& result) {
    EXPECT_TRUE(false) << "Can't use base Expectation class";
  }
};

struct UntimedReadExpectation : public Expectation {
  UntimedReadExpectation(std::vector<char> data) { expectedPayload = data; }
  void expect(ExpectationResult& res) override {
    EXPECT_THAT(expectedPayload, ::testing::ContainerEq(res.resultPayload))
        << "Failure: " << message;
  }
};

struct ReadRequestExpectation : public Expectation {
  ReadRequestExpectation(std::vector<char> data, uint64_t ticks) {
    expectedPayload = data;
    expectedTicks = ticks;
  };
  void expect(ExpectationResult& res) override {
    uint64_t elapsed = res.endTick - startTick;
    EXPECT_EQ(elapsed, expectedTicks) << message;
    EXPECT_THAT(expectedPayload, testing::ContainerEq(res.resultPayload))
        << "Failure: " << message;
  }
};

struct WriteRequestExpectation : public Expectation {
  WriteRequestExpectation(uint64_t ticks) { expectedTicks = ticks; }
  void expect(ExpectationResult& res) override {
    uint64_t elapsed = res.endTick - startTick;
    EXPECT_GE(elapsed, expectedTicks) << "Failure: " << message;
  }
};

class CacheTestEngine : public testing::Test {
 public:
  uint8_t assosciativity = 4;
  uint16_t clw = 4;
  uint32_t cacheSize = 4 * 1024;
  uint16_t hitLatency = 2;
  uint16_t accessLatency = 1;
  uint16_t missPenalty = 4;
  uint64_t memorySize = 1024 * 16;

  CacheTestEngine();

  std::unique_ptr<Mem> memory = std::make_unique<SimpleMem>(memorySize);
  SetAssosciativeCache cache = SetAssosciativeCache(
      clw, assosciativity, cacheSize, {hitLatency, accessLatency, missPenalty},
      std::make_unique<PIPT>(cacheSize, clw, assosciativity));

  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> freePort =
      std::make_shared<Port<std::unique_ptr<MemPacket>>>();

  std::vector<std::unique_ptr<MemPacket>> responses;
  PortMediator<std::unique_ptr<MemPacket>> cpuToCache;
  PortMediator<std::unique_ptr<MemPacket>> cacheToMem;

  uint64_t ticks = 0;
  std::vector<std::shared_ptr<Event>> events;

  void rebuildWithSimpleMem() {
    memory = std::make_unique<SimpleMem>(memorySize);
    rebuild();
  }

  void rebuildWithFixedLatencyMemory(uint16_t latency) {
    memory = std::make_unique<FixedLatencyMemory>(memorySize, latency);
    rebuild();
  }

  void tick() { ticks++; }

  void setExpectation(uint64_t id, Expectation* expectation) {
    expectation->startTick = ticks;
    expectations.insert({id, expectation});
  }

  void setExpectationResult(uint64_t id, ExpectationResult result) {
    expectationResults.insert({id, result});
  }

  void matchExpectationsAndResults() {
    for (auto pair : expectations) {
      auto itr = expectationResults.find(pair.first);
      pair.second->expect(itr->second);
    }
  }

  void run() {
    for (uint16_t x = 0; x < events.size(); x++) {
      auto event = events[x];
      event->doEvent(this, x);
    }
    matchExpectationsAndResults();
  }

  virtual void TearDown() {
    for (auto pair : expectations) {
      delete pair.second;
    }
  }

  template <EventType __type>
  EventBuilder<__type>& newEvent();

 private:
  std::map<uint64_t, Expectation*> expectations;
  std::map<uint64_t, ExpectationResult> expectationResults;

  void setup() {
    freePort->registerReceiver([&](std::unique_ptr<MemPacket> pkt) {
      ExpectationResult res;
      res.endTick = ticks + 1;
      if (pkt->isRead()) {
        res.resultPayload = pkt->payload();
      }
      expectationResults.insert({pkt->id_, res});
    });

    auto memPort = memory->initPort();
    auto cacheTopPort = cache.initTopPort();
    auto cacheBottomPort = cache.initBottomPort();

    cpuToCache.connect(freePort, cacheTopPort);
    cacheToMem.connect(cacheBottomPort, memPort);
  }

  void rebuild() {
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
};
