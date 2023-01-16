#include "gtest/gtest.h"
#include "simeng/pipeline/BalancedPortAllocator.hh"

namespace simeng {
namespace pipeline {

// Tests that the balanced port allocator can correctly allocate a port
TEST(BalancedPortAllocatorTest, Allocate) {
  std::vector<std::vector<uint16_t>> arrangement = {{0}};
  auto simple = BalancedPortAllocator(arrangement);
  EXPECT_EQ(simple.allocate({0}), 0);
}

// Tests that the balanced port allocator selects the correct port when there's
// multiple ports
TEST(BalancedPortAllocatorTest, AllocateLimited) {
  auto limited = BalancedPortAllocator({{0}, {1}, {2}});
  EXPECT_EQ(limited.allocate({1}), 1);
}

// Tests that the balanced port allocator will balance across two equal ports
// when allocated in sequence
TEST(BalancedPortAllocatorTest, BalanceEven) {
  auto portAllocator = BalancedPortAllocator({{0}, {1}});
  auto first = portAllocator.allocate({0, 1});
  auto second = portAllocator.allocate({0, 1});
  EXPECT_NE(first, second);
}

// Tests that the balanced port allocator will choose the less-contended port in
// an uneven port allocation
TEST(BalancedPortAllocatorTest, BalanceUneven) {
  auto portAllocator = BalancedPortAllocator({{0}, {1}});
  // Allocate for port 0 twice
  EXPECT_EQ(portAllocator.allocate({0}), 0);
  EXPECT_EQ(portAllocator.allocate({0}), 0);

  // Port 0 and 1 allocation should go to port 1 to be balanced
  EXPECT_EQ(portAllocator.allocate({0, 1}), 1);
}

// Tests that the balanced port allocator will take deallocations into account
// when balancing
TEST(BalancedPortAllocatorTest, Deallocate) {
  auto portAllocator = BalancedPortAllocator({{0, 1}, {0, 2}});
  // Allocate to port 0 twice
  EXPECT_EQ(portAllocator.allocate({0}), 0);
  EXPECT_EQ(portAllocator.allocate({0}), 0);

  // Port 1 allocation
  EXPECT_EQ(portAllocator.allocate({1}), 1);

  // Deallocate twice from port 0
  portAllocator.deallocate(0);
  portAllocator.deallocate(0);

  // Next allocation should go to port 0, rather than port 1, if deallocation
  // was respected
  EXPECT_EQ(portAllocator.allocate({0, 1}), 0);
}

// Tests correct allocation when multiple ports support an instruction
TEST(BalancedPortAllocatorTest, MultipleSupportedPorts) {
  auto portAllocator =
      BalancedPortAllocator({{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}});

  // Ensure multi-port support is correctly balanced
  for (int i = 0; i < 10; i++) {
    EXPECT_EQ(portAllocator.allocate({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}), i);
  }
}

}  // namespace pipeline
}  // namespace simeng
