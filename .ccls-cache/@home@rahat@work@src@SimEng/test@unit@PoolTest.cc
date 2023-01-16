#include <random>
#include <vector>

#include "gtest/gtest.h"
#include "simeng/Pool.hh"

namespace {

// Tests that memory is reused correctly
TEST(FixedPoolTest, MemoryReused) {
  auto p = simeng::fixedPool_<10, 2>();
  void* ptr = p.allocate();
  void* ptr2 = p.allocate();
  // The pool will grow by 4. Total size is 6.
  void* ptr3 = p.allocate();

  ASSERT_NE(ptr, nullptr);
  ASSERT_NE(ptr2, nullptr);
  ASSERT_NE(ptr3, nullptr);

  p.deallocate(ptr);
  p.deallocate(ptr2);
  p.deallocate(ptr3);

  void* ptr4 = p.allocate();
  void* ptr5 = p.allocate();
  void* ptr6 = p.allocate();

  EXPECT_EQ(ptr3, ptr4);
  EXPECT_EQ(ptr5, ptr2);
  EXPECT_EQ(ptr6, ptr);
}

// Tests that the pointer returned by allocate is sufficiently aligned
TEST(FixedPoolTest, Alignment) {
  auto p = simeng::fixedPool_<25>();
  uintptr_t ptr = reinterpret_cast<uintptr_t>(p.allocate());

  EXPECT_EQ(ptr & (alignof(std::max_align_t) - 1), 0);
}

// Tests general usage works correctly. To be tested with sanitizers
TEST(FixedPoolTest, GeneralUsage) {
  std::mt19937 gen;
  std::uniform_int_distribution<> distribution(0, 1);

  auto p = simeng::fixedPool_<10>();
  for (size_t i = 0; i < 65535; i++) {
    void* ptr = p.allocate();

    // Allocation was successful.
    ASSERT_NE(ptr, nullptr);

    // Test that we can access all the bytes.
    memset(ptr, 0, 10);

    // Randomly deallocate to simulate real usage.
    if (distribution(gen)) p.deallocate(ptr);
  }
}

}  // namespace
