#include <iostream>

#include "Friends.hh"
#include "gtest/gtest.h"
#include "simeng/kernel/PageFrameAllocator.hh"
using namespace TestFriends;
using namespace simeng::kernel;
namespace {

TEST(PFATest, AllocateSinglePageFrame) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  allctr->allocate(4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];
  uint64_t num = 1;
  num <<= 63;
  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096);
  ASSERT_EQ(entry->size_, 4096);
};

TEST(PFATest, AllocateMultiplePageFramesIndividually) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  allctr->allocate(4096);
  allctr->allocate(4096);
  allctr->allocate(4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];

  uint64_t num = 0;
  uint64_t bit = 1;
  num |= (bit << 63);
  num |= (bit << 62);
  num |= (bit << 61);

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 3);
  ASSERT_EQ(entry->size_, 4096 * 3);
};

TEST(PFATest, AllocateMultiplePageFramesCollectively1) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  allctr->allocate(4 * 4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];

  uint64_t num = 0;
  uint64_t bit = 1;
  num |= (bit << 63);
  num |= (bit << 62);
  num |= (bit << 61);
  num |= (bit << 60);

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 4);
  ASSERT_EQ(entry->size_, 4096 * 4);
};

TEST(PFATest, AllocatePageFramesCollectively2) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  allctr->allocate(4096);
  allctr->allocate(4096);
  allctr->allocate(4 * 4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];

  uint64_t num = 0;
  uint64_t bit = 1;
  num |= (bit << 63);
  num |= (bit << 62);
  num |= (bit << 61);
  num |= (bit << 60);
  num |= (bit << 59);
  num |= (bit << 58);

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 6);
  ASSERT_EQ(entry->size_, 4096 * 6);
};

TEST(PFATest, AllocateMaximumPageFramesPerAllocEntry) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  allctr->allocate(64 * 4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];

  uint64_t num = ~0;

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 64);
  ASSERT_EQ(entry->size_, 4096 * 64);
};

TEST(PFATest, AllocateSizeGreaterThanSizeLeftInCurrentAllocEntry) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  // allocate 60 Pages, space only left for 4.
  allctr->allocate(60 * 4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];

  uint64_t num = ~0;
  num <<= 4;

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 60);
  ASSERT_EQ(entry->size_, 4096 * 60);

  // This should create a new AllocEntry because the existing entry doesn't have
  // enough space.
  uint64_t addr = allctr->allocate(6 * 4096);
  ASSERT_EQ(addr, 64 * 4096);

  entries = allctrFrnd->getEntries();
  entry = entries[1];
  EXPECT_TRUE(entry != NULL);

  ASSERT_EQ(entry->startAddr_, 4096 * 64 * 1);
  ASSERT_EQ(entry->nextFreeAddr, (4096 * 64 * 1) + (6 * 4096));
  ASSERT_EQ(entry->size_, 4096 * 6);
};

TEST(PFATest, AllocateMultipleMaxAllocEntries) {
  simeng::kernel::PageFrameAllocator* allctr =
      new simeng::kernel::PageFrameAllocator();
  PFAFriend* allctrFrnd = new PFAFriend(allctr);
  // allocate 60 Pages, space only left for 4.
  allctr->allocate(3 * 64 * 4096);
  std::array<AllocEntry*, 16> entries = allctrFrnd->getEntries();
  AllocEntry* entry = entries[0];
  uint64_t num = ~0;

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 0);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 64);
  ASSERT_EQ(entry->size_, 4096 * 64);

  entry = entries[1];

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 4096 * 64);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 64 * 2);
  ASSERT_EQ(entry->size_, 4096 * 64);

  entry = entries[2];

  ASSERT_EQ(entry->track, num);
  ASSERT_EQ(entry->startAddr_, 4096 * 64 * 2);
  ASSERT_EQ(entry->nextFreeAddr, 4096 * 64 * 3);
  ASSERT_EQ(entry->size_, 4096 * 64);
};

}  // namespace
