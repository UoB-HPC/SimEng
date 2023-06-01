#include "CacheTestEngine.hh"
#include "EventBuilder.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"

namespace {

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

TEST_F(CacheTestEngine, UntimedRead) {
  newEvent<EventType::UWrite>().target(0, 4, {'2', '2', '2', '2'}).add();
  newEvent<EventType::URead>()
      .target(0, 4)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  run();
}

TEST_F(CacheTestEngine, CacheReadMiss) {
  newEvent<EventType::UWrite>().target(0, 4, {'2', '2', '2', '2'}).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(6)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  run();
}

TEST_F(CacheTestEngine, CacheReadHit) {
  newEvent<EventType::UWrite>().target(0, 4, {'2', '2', '2', '2'}).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(6)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(3)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

TEST_F(CacheTestEngine, CacheWriteMiss) {
  newEvent<EventType::Write>()
      .target(0, 4, {'1', '1', '1', '1'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(3)
      .expectedResponse({'1', '1', '1', '1'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

TEST_F(CacheTestEngine, CacheWriteHit) {
  newEvent<EventType::Write>()
      .target(0, 4, {'1', '1', '1', '1'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Write>()
      .target(0, 4, {'2', '2', '2', '2'})
      .expectedElapsedTicks(3)
      .add();
  newEvent<EventType::Tick>().tickFor(10).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(3)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

TEST_F(CacheTestEngine, MultipleReadsToSameCacheLine) {
  newEvent<EventType::UWrite>().target(0, 2, {'2', '2'}).add();
  newEvent<EventType::UWrite>().target(2, 2, {'3', '3'}).add();
  newEvent<EventType::URead>()
      .target(0, 4)
      .expectedResponse({'2', '2', '3', '3'})
      .add();
  newEvent<EventType::Read>()
      .target(0, 2)
      .expectedElapsedTicks(6)
      .expectedResponse({'2', '2'})
      .add();
  newEvent<EventType::Read>()
      .target(0, 2)
      .expectedElapsedTicks(6)
      .expectedResponse({'2', '2'})
      .add();
  newEvent<EventType::Read>()
      .target(2, 2)
      .expectedElapsedTicks(6)
      .expectedResponse({'3', '3'})
      .add();
  newEvent<EventType::Read>()
      .target(2, 2)
      .expectedElapsedTicks(6)
      .expectedResponse({'3', '3'})
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Read>()
      .target(2, 2)
      .expectedElapsedTicks(3)
      .expectedResponse({'3', '3'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

TEST_F(CacheTestEngine, MultipleWritesToSameCacheLine) {
  newEvent<EventType::UWrite>().target(0, 2, {'2', '2'}).add();
  newEvent<EventType::UWrite>().target(2, 2, {'3', '3'}).add();
  newEvent<EventType::URead>()
      .target(0, 4)
      .expectedResponse({'2', '2', '3', '3'})
      .add();
  newEvent<EventType::Write>()
      .target(0, 2, {'2', '2'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Write>()
      .target(0, 2, {'2', '2'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Write>()
      .target(2, 2, {'3', '3'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Write>()
      .target(2, 2, {'3', '3'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Read>()
      .target(2, 2)
      .expectedElapsedTicks(3)
      .expectedResponse({'3', '3'})
      .add();
  newEvent<EventType::Read>()
      .target(0, 2)
      .expectedElapsedTicks(3)
      .expectedResponse({'2', '2'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

TEST_F(CacheTestEngine, InterleavedReadAndWritesToTheSameCacheLine) {
  newEvent<EventType::Write>()
      .target(0, 4, {'2', '2', '2', '2'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedResponse({'2', '2', '2', '2'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Write>()
      .target(0, 4, {'3', '3', '3', '3'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedResponse({'3', '3', '3', '3'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Write>()
      .target(0, 4, {'4', '4', '4', '4'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Tick>().tickFor(6).add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedElapsedTicks(3)
      .expectedResponse({'4', '4', '4', '4'})
      .add();
  newEvent<EventType::Tick>().tickFor(3).add();
  run();
}

}  // namespace
