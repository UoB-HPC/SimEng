#include "CacheTestEngine.hh"
#include "EventBuilder.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"

namespace {

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

TEST_F(CacheTestEngine, CacheTest1) {
  newEvent<EventType::UWrite>().target(0, 4, {'2', '2', '2', '2'}).add();
  newEvent<EventType::URead>()
      .target(0, 4)
      .expectedResponse({'2', '2', '2', '2'})
      .add();
  newEvent<EventType::Read>()
      .target(0, 4)
      .expectedResponse({'2', '2', '2', '2'})
      .expectedElapsedTicks(6)
      .add();
  newEvent<EventType::Tick>().tickFor(10);

  run();
}

}  // namespace
