#include "gtest/gtest.h"
#include "simeng/pipeline/BalancedPortAllocator.hh"

namespace simeng {
namespace pipeline {

// Tests that the balanced port allocator can correctly allocate a port for a
// supported group
TEST(BalancedPortAllocatorTest, Allocate) {
  std::vector<std::vector<uint16_t>> arrangement = {{0}};
  auto simple = BalancedPortAllocator(arrangement);
  EXPECT_EQ(simple.allocate(0), 0);
}

// Tests that the balanced port allocator will allocate correctly when there's
// only one port that supports the supplied group
TEST(BalancedPortAllocatorTest, AllocateLimited) {
  auto limited = BalancedPortAllocator({{0}, {1}});
  EXPECT_EQ(limited.allocate(1), 1);
}

// Tests that the balanced port allocator will balance across two equal ports
// when allocated in sequence
TEST(BalancedPortAllocatorTest, BalanceEven) {
  auto portAllocator = BalancedPortAllocator({{0}, {0}});
  auto first = portAllocator.allocate(0);
  auto second = portAllocator.allocate(0);
  EXPECT_NE(first, second);
}

// Tests that the balanced port allocator will choose the less-contended port in
// an uneven port configuration
TEST(BalancedPortAllocatorTest, BalanceUneven) {
  auto portAllocator = BalancedPortAllocator({{0, 1}, {0}});
  // Allocate for group 1 twice; port 0 is only viable candidate
  EXPECT_EQ(portAllocator.allocate(1), 0);
  EXPECT_EQ(portAllocator.allocate(1), 0);

  // Group 0 allocation should go to port 1 to be balanced
  EXPECT_EQ(portAllocator.allocate(0), 1);
}

// Tests that the balanced port allocator will take deallocations into account
// when balancing
TEST(BalancedPortAllocatorTest, Deallocate) {
  auto portAllocator = BalancedPortAllocator({{0, 1}, {0, 2}});
  // Allocate to group 1 twice; must go to port 0
  EXPECT_EQ(portAllocator.allocate(1), 0);
  EXPECT_EQ(portAllocator.allocate(1), 0);

  // Group 2 allocation must go to port 1
  EXPECT_EQ(portAllocator.allocate(2), 1);

  // Deallocate twice from port 0
  portAllocator.deallocate(0);
  portAllocator.deallocate(0);

  // Next allocation should go to port 0, rather than port 1, if deallocation
  // was respected
  EXPECT_EQ(portAllocator.allocate(0), 0);
}

}  // namespace pipeline
}  // namespace simeng
