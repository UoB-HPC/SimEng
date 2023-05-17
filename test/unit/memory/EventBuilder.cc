#include "EventBuilder.hh"

#include <memory>

#include "CacheTestEngine.hh"

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

void EventBuilderBase::addEvent(std::shared_ptr<Event> event) {
  engine_->events.push_back(event);
}

EventBuilder<EventType::Read>::EventBuilder(CacheTestEngine* engine)
    : EventBuilderBase(engine){};

void EventBuilder<EventType::Read>::add() {
  verify();
  addEvent(std::make_shared<MemoryRequestEvent>(
      std::move(request_),
      new ReadRequestExpectation(expectedResponse_, expectedElapsedTicks_)));
  reset();
}

EventBuilder<EventType::Write>::EventBuilder(CacheTestEngine* engine)
    : EventBuilderBase(engine){};

void EventBuilder<EventType::Write>::add() {
  verify();
  addEvent(std::make_shared<MemoryRequestEvent>(
      std::move(request_), new WriteRequestExpectation(expectedElapsedTicks_)));
  reset();
}

EventBuilder<EventType::Tick>::EventBuilder(CacheTestEngine* engine)
    : EventBuilderBase(engine) {}

void EventBuilder<EventType::Tick>::add() {
  verify();
  addEvent(std::make_shared<TickEvent>(tickFor_));
  reset();
}

EventBuilder<EventType::URead>::EventBuilder(CacheTestEngine* engine)
    : EventBuilderBase(engine) {}

void EventBuilder<EventType::URead>::add() {
  verify();
  addEvent(std::make_shared<UntimedReadEvent>(
      paddr_, size_, new UntimedReadExpectation(expectedResult_)));
  reset();
}

EventBuilder<EventType::UWrite>::EventBuilder(CacheTestEngine* engine)
    : EventBuilderBase(engine) {}

void EventBuilder<EventType::UWrite>::add() {
  verify();
  addEvent(std::make_shared<UntimedWriteEvent>(paddr_, size_, payload_));
  reset();
}
