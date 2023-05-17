#include "CacheTestEngine.hh"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

CacheTestEngine::CacheTestEngine() { setup(); };

template <>
EventBuilder<EventType::Read>& CacheTestEngine::newEvent() {
  static EventBuilder<EventType::Read> builder(nullptr);
  if (!builder.hasEngine()) {
    builder.addEngine(this);
  }
  return builder;
};

template <>
EventBuilder<EventType::Write>& CacheTestEngine::newEvent() {
  static EventBuilder<EventType::Write> builder(nullptr);
  if (!builder.hasEngine()) {
    builder.addEngine(this);
  }
  return builder;
};

template <>
EventBuilder<EventType::Tick>& CacheTestEngine::newEvent() {
  static EventBuilder<EventType::Tick> builder(nullptr);
  if (!builder.hasEngine()) {
    builder.addEngine(this);
  }
  return builder;
};

template <>
EventBuilder<EventType::URead>& CacheTestEngine::newEvent() {
  static EventBuilder<EventType::URead> builder(nullptr);
  if (!builder.hasEngine()) {
    builder.addEngine(this);
  }
  return builder;
};

template <>
EventBuilder<EventType::UWrite>& CacheTestEngine::newEvent() {
  static EventBuilder<EventType::UWrite> builder(nullptr);
  if (!builder.hasEngine()) {
    builder.addEngine(this);
  }
  return builder;
};

void UntimedReadEvent::doEvent(CacheTestEngine* engine, uint16_t index) {
  expectation->message = serialise(index);
  expectation->startTick = engine->ticks;
  engine->setExpectation(id, expectation);
  auto vec = engine->memory->getUntimedData(paddr, size);
  engine->setExpectationResult(id, {engine->ticks, vec});
}

void TickEvent::doEvent(CacheTestEngine* engine, uint16_t index) {
  for (uint16_t x = 0; x < tickFor; x++) {
    engine->cache.tick();
    engine->memory->tick();
    engine->tick();
  }
}

void MemoryRequestEvent::doEvent(CacheTestEngine* engine, uint16_t index) {
  expectation->message = serialise(index);
  expectation->startTick = engine->ticks;
  engine->setExpectation(id, expectation);
  engine->freePort->send(std::move(request));
}

void UntimedWriteEvent::doEvent(CacheTestEngine* engine, uint16_t index) {
  engine->memory->sendUntimedData(data, paddr, size);
}

std::string UntimedReadEvent::serialise(uint16_t index) {
  std::stringstream ss;
  ss << "Untimed Read Event at index: " << index << " with paddr: " << paddr
     << " and size: " << size;
  return ss.str();
}

std::string UntimedWriteEvent::serialise(uint16_t index) {
  std::stringstream ss;
  ss << "Untimed Write Event at index: " << index << " with paddr: " << paddr
     << " and size: " << size << " and data: { ";
  for (auto ch : data) {
    ss << ch << " ";
  }
  ss << "}";
  return ss.str();
}

std::string TickEvent::serialise(uint16_t index) {
  return "Tick Event at index: " + std::to_string(index) +
         " ( tick for: " + std::to_string(tickFor) + " ticks )";
}

std::string MemoryRequestEvent::serialise(uint16_t index) {
  std::stringstream ss;
  if (request->isRead()) {
    ss << "Memory Read Event at index: " << index
       << " with paddr: " << request->paddr_ << " and size: " << request->size_;

  } else {
    ss << "Memory Write Event at index: " << index
       << " with paddr: " << request->paddr_ << ", size: " << request->size_
       << " and data: { ";
    for (auto ch : request->payload()) {
      ss << ch << " ";
    }
    ss << "}";
  }
  return ss.str();
}
