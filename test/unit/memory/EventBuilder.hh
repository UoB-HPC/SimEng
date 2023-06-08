#pragma once
#include <gtest/gtest.h>

#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "simeng/memory/MemPacket.hh"

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

class CacheTestEngine;
struct Event;

enum class EventType { Read, Write, URead, UWrite, Tick };

class EventBuilderBase {
 public:
  EventBuilderBase(CacheTestEngine* engine) : engine_(engine){};
  bool hasEngine() { return engine_ != nullptr; }
  void addEngine(CacheTestEngine* engine) { engine_ = engine; }

 protected:
  CacheTestEngine* engine_ = nullptr;
  void addEvent(std::shared_ptr<Event> event);
  virtual void reset() = 0;
};

template <EventType _type>
class EventBuilder;

template <>
class EventBuilder<EventType::Read> : public EventBuilderBase {
 public:
  EventBuilder(CacheTestEngine* engine);

  EventBuilder<EventType::Read>& expectedResponse(std::vector<char> data) {
    expectedResponse_ = data;
    return *this;
  }

  EventBuilder<EventType::Read>& expectedElapsedTicks(uint16_t ticks) {
    expectedElapsedTicks_ = ticks;
    return *this;
  };

  EventBuilder<EventType::Read>& target(uint64_t paddr, uint16_t size) {
    request_ =
        CPUMemoryPacket(MemoryAccessType::READ, paddr, paddr, size, 0, 0, 0);
    return *this;
  }

  void add();

 private:
  CPUMemoryPacket request_;
  uint64_t expectedElapsedTicks_ = UINT64_MAX;
  std::vector<char> expectedResponse_;

  void reset() override {
    request_ = CPUMemoryPacket();
    request_.size_ = 0;
    expectedElapsedTicks_ = UINT64_MAX;
    expectedResponse_.clear();
  }
  void verify() {
    bool correct = true;
    correct = correct && (request_.size_ != 0);
    correct = correct && (expectedElapsedTicks_ != UINT64_MAX);
    correct = correct && expectedResponse_.size();
    EXPECT_TRUE(correct)
        << "Please Specify expectedResponse, expectedElapsedTicks, and target "
           "parameters required for ReadRequestMemoryEvent to event builder"
        << std::endl;
  }
};

template <>
class EventBuilder<EventType::Write> : public EventBuilderBase {
 public:
  EventBuilder(CacheTestEngine* engine);

  EventBuilder<EventType::Write>& expectedElapsedTicks(uint16_t ticks) {
    expectedElapsedTicks_ = ticks;
    return *this;
  };

  EventBuilder<EventType::Write>& target(uint64_t paddr, uint16_t size,
                                         std::vector<char> data) {
    request_ =
        CPUMemoryPacket(MemoryAccessType::WRITE, paddr, paddr, size, 0, 0, 0);
    request_.payload_ = data;
    return *this;
  }

  void add();

 private:
  CPUMemoryPacket request_;
  uint64_t expectedElapsedTicks_ = UINT64_MAX;

  void reset() override {
    request_ = CPUMemoryPacket();
    request_.size_ = 0;
    expectedElapsedTicks_ = UINT64_MAX;
  }
  void verify() {
    bool correct = true;
    correct = correct && (request_.size_ != 0);
    correct = correct && (expectedElapsedTicks_ != UINT64_MAX);
    EXPECT_TRUE(correct)
        << "Specify all parameters for WriteMemoryEvent to event builder"
        << std::endl;
  }
};

template <>
class EventBuilder<EventType::Tick> : public EventBuilderBase {
 public:
  EventBuilder(CacheTestEngine* engine);

  EventBuilder<EventType::Tick>& tickFor(uint16_t ticks) {
    tickFor_ = ticks;
    return *this;
  }

  void add();

 private:
  uint16_t tickFor_ = UINT16_MAX;
  void reset() override { tickFor_ = UINT16_MAX; }
  void verify() {
    bool correct = true;
    correct = correct && (tickFor_ != UINT16_MAX);
    EXPECT_TRUE(correct)
        << "Specify the tickFor parameter for TickEvent to event builder"
        << std::endl;
  }
};

template <>
class EventBuilder<EventType::URead> : public EventBuilderBase {
 public:
  EventBuilder(CacheTestEngine* engine);

  EventBuilder<EventType::URead>& expectedResponse(std::vector<char> data) {
    expectedResult_ = data;
    return *this;
  }

  EventBuilder<EventType::URead>& target(uint64_t paddr, uint16_t size) {
    paddr_ = paddr;
    size_ = size;
    return *this;
  }

  void add();

 private:
  uint64_t paddr_ = UINT64_MAX;
  uint64_t size_ = UINT64_MAX;
  std::vector<char> expectedResult_;

  void reset() override {
    paddr_ = UINT64_MAX;
    size_ = UINT64_MAX;
    expectedResult_.clear();
  }

  void verify() {
    bool correct = true;
    correct = correct && (paddr_ != UINT64_MAX);
    correct = correct && (size_ != UINT64_MAX);
    correct = correct && (expectedResult_.size());
    EXPECT_TRUE(correct) << "Specify expectedResult and target parameters for "
                            "UntimedReadEvent to event builder"
                         << std::endl;
  }
};

template <>
class EventBuilder<EventType::UWrite> : public EventBuilderBase {
 public:
  EventBuilder(CacheTestEngine* engine);

  EventBuilder<EventType::UWrite>& target(uint64_t paddr, uint16_t size,
                                          std::vector<char> data) {
    paddr_ = paddr;
    size_ = size;
    payload_ = data;
    return *this;
  }

  void add();

 private:
  uint64_t paddr_ = UINT64_MAX;
  uint64_t size_ = UINT64_MAX;
  std::vector<char> payload_;

  void reset() override {
    paddr_ = UINT64_MAX;
    size_ = UINT64_MAX;
    payload_.clear();
  }

  void verify() {
    bool correct = true;
    correct = correct && (paddr_ != UINT64_MAX);
    correct = correct && (size_ != UINT64_MAX);
    correct = correct && (payload_.size());
    EXPECT_TRUE(correct)
        << "Specify all target parameter for UntimedWriteEvent to event builder"
        << std::endl;
  }
};
