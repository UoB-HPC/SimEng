#include "gtest/gtest.h"
#include "simeng/pipeline/BalancedPortAllocator.hh"

namespace simeng {
namespace pipeline {

// Tests that the balanced port allocator can correctly allocate a port for a
// supported group
TEST(BalancedPortAllocatorTest, Allocate) {
  std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> arrangement = {
    {{{0,0}}}
  };
  auto simple = BalancedPortAllocator(arrangement);
  EXPECT_EQ(simple.allocate(1), 0);
}

// Tests that the balanced port allocator will allocate correctly when there's
// only one port that supports the supplied group
TEST(BalancedPortAllocatorTest, AllocateLimited) {
  auto limited = BalancedPortAllocator({
    {{{0,0}}}, 
    {{{1,0}}}
  });
  EXPECT_EQ(limited.allocate(2), 1);
}

// Tests that the balanced port allocator will balance across two equal ports
// when allocated in sequence
TEST(BalancedPortAllocatorTest, BalanceEven) {
  auto portAllocator = BalancedPortAllocator({
    {{{0,0}}}, 
    {{{0,0}}}
  });
  auto first = portAllocator.allocate(1);
  auto second = portAllocator.allocate(1);
  EXPECT_NE(first, second);
}

// Tests that the balanced port allocator will choose the less-contended port in
// an uneven port configuration
TEST(BalancedPortAllocatorTest, BalanceUneven) {
  auto portAllocator = BalancedPortAllocator({
    {{{0,0}},{{1,0}}}, 
    {{{0,0}}}
  });
  // Allocate for group 1 twice; port 0 is only viable candidate
  EXPECT_EQ(portAllocator.allocate(2), 0);
  EXPECT_EQ(portAllocator.allocate(2), 0);

  // Group 0 allocation should go to port 1 to be balanced
  EXPECT_EQ(portAllocator.allocate(1), 1);
}

// Tests that the balanced port allocator will take deallocations into account
// when balancing
TEST(BalancedPortAllocatorTest, Deallocate) {
  auto portAllocator = BalancedPortAllocator({
    {{{0,0}},{{1,0}}},
    {{{0,0}},{{2,0}}},
  });
  // Allocate to group 1 twice; must go to port 0
  EXPECT_EQ(portAllocator.allocate(2), 0);
  EXPECT_EQ(portAllocator.allocate(2), 0);

  // Group 2 allocation must go to port 1
  EXPECT_EQ(portAllocator.allocate(4), 1);

  // Deallocate twice from port 0
  portAllocator.deallocate(0);
  portAllocator.deallocate(0);

  // Next allocation should go to port 0, rather than port 1, if deallocation
  // was respected
  EXPECT_EQ(portAllocator.allocate(1), 0);
}

// Tests correct allocation when ports share complex groups
TEST(BalancedPortAllocatorTest, ComplexSharedPorts) {
  auto portAllocator = BalancedPortAllocator({
    {{{4,0}, {1,1}, {2,1}, {3,1}}}, // PORT 0
    {{{0,0}, {1,1}, {2,1}}}, // PORT 1
    {{{4,0}, {1,1}, {2,1}}}, // PORT 2
    {{{0,0}, {1,1}, {3,1}}}, // PORT 3
    {{{5,0}, {1,1}, {4,1}},
     {{0,0}}}, // PORT 4
    {{{5,0}, {1,1}, {4,1}},
     {{6,0}, {1,1}, {4,1}},
     {{0,0}}}, // PORT 5
    {{{7,0}}} // PORT 6
  });

  // Ensure non-shared groups go to correct port first
  EXPECT_EQ(portAllocator.allocate(128), 6);
  EXPECT_EQ(portAllocator.allocate(64), 5);
  EXPECT_EQ(portAllocator.allocate(66), 5);
  EXPECT_EQ(portAllocator.allocate(82), 5);
  EXPECT_EQ(portAllocator.allocate(11), 3);
  EXPECT_EQ(portAllocator.allocate(7), 1);
  EXPECT_EQ(portAllocator.allocate(30), 0);

  // Group 1 shared between ports 1/3/4/5
  EXPECT_EQ(portAllocator.allocate(1), 4);
  EXPECT_EQ(portAllocator.allocate(1), 1);
  EXPECT_EQ(portAllocator.allocate(1), 3);
  EXPECT_EQ(portAllocator.allocate(1), 4);
  EXPECT_EQ(portAllocator.allocate(1), 1);
  EXPECT_EQ(portAllocator.allocate(1), 3);
  EXPECT_EQ(portAllocator.allocate(1), 4);
  EXPECT_EQ(portAllocator.allocate(1), 1);
  EXPECT_EQ(portAllocator.allocate(1), 3);
  EXPECT_EQ(portAllocator.allocate(1), 4);
  EXPECT_EQ(portAllocator.allocate(1), 5);

  // Group 3 shared between ports 1/3
  EXPECT_EQ(portAllocator.allocate(3), 1);
  EXPECT_EQ(portAllocator.allocate(3), 3);

  // Group 16/18/22 shared between ports 0/2
  EXPECT_EQ(portAllocator.allocate(16), 2);
  EXPECT_EQ(portAllocator.allocate(16), 0);
  EXPECT_EQ(portAllocator.allocate(18), 2);
  EXPECT_EQ(portAllocator.allocate(18), 0);
  EXPECT_EQ(portAllocator.allocate(22), 2);
  EXPECT_EQ(portAllocator.allocate(22), 0);

  // Group 32 shared between ports 4/5
  EXPECT_EQ(portAllocator.allocate(32), 4);
  EXPECT_EQ(portAllocator.allocate(32), 5);
}

// Test that extreme group cases
TEST(BalancedPortAllocatorTest, ExtremeCases) {
  auto portAllocator = BalancedPortAllocator({
    {{}}, // PORT 0
    {{{0,0}, {1,0}, {2,0}, {3,0}, {4,0}}}, // PORT 1
    {{{0,1}, {1,1}, {2,1}, {3,1}, {4,1}}} // PORT 2
  });

  for (int i = 0; i < 32; i++) {
    if(i == 0) {
      EXPECT_EQ(portAllocator.allocate(i), 0);
    }
    else if(i == 31) {
      EXPECT_EQ(portAllocator.allocate(i), 1);
    } else {
      EXPECT_EQ(portAllocator.allocate(i), 2);
    }
  }
}

}  // namespace pipeline
}  // namespace simeng
