#include <iostream>

#include "TestFriends.hh"
#include "gtest/gtest.h"
#include "simeng/OS/PageFrameAllocator.hh"
using namespace simeng::OS;
namespace {

TEST(PFATest, AllocateSinglePageFrame) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(4096);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 4096);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 4096);
};

TEST(PFATest, AllocateMultiplePageFramesIndividually) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(4096);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 4096);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 4096);

  addr = allctr.allocate(4096);
  ASSERT_EQ(addr, 4096);
  ASSERT_EQ(allctr.getNextFreeAddr(), 8192);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 8192);
};

TEST(PFATest, AllocateMultiplePageFramesCollectively) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(4096 * 4);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 16384);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 16384);

  addr = allctr.allocate(4096 * 4);
  ASSERT_EQ(addr, 16384);
  ASSERT_EQ(allctr.getNextFreeAddr(), 16384 * 2);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - (16384 * 2));
};

TEST(PFATest, AllocateSizeSmallerThanPageSize) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(381);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 4096);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 4096);
};

TEST(PFATest, AllocateUnalignedSizeGreaterThanPageSize) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(8227);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 12288);
  ASSERT_EQ(allctr.getSizeLeft(), memSize - 12288);
};

TEST(PFATest, AllocateMaximumSize) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  uint64_t addr = allctr.allocate(1024000000);
  ASSERT_EQ(addr, 0);
  ASSERT_EQ(allctr.getNextFreeAddr(), 1024000000);
  ASSERT_EQ(allctr.getSizeLeft(), 0);
};

TEST(PFATest, AllocateSizeGreaterThanMaxAllocationSize) {
  uint64_t memSize = 1024000000;
  simeng::OS::PageFrameAllocator allctr =
      simeng::OS::PageFrameAllocator(memSize);
  EXPECT_EXIT({ allctr.allocate(1025000000); }, ::testing::ExitedWithCode(1),
              "Cannot allocate more page frames! Increase system memory.");
};

}  // namespace
