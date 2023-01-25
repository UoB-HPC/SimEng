#include <sys/mman.h>

#include "gtest/gtest.h"
#include "simeng/kernel/MemRegion.hh"

using namespace simeng::kernel;

namespace {

TEST(MemRegionTest, UpdateBrkRegion) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);
  ASSERT_EQ(memRegion.getBrk(), 0);
  ASSERT_EQ(memRegion.updateBrkRegion(1000), 4096);
  ASSERT_EQ(memRegion.updateBrkRegion(0), 4096);
  ASSERT_EQ(memRegion.updateBrkRegion(10365), 12288);
  ASSERT_EQ(memRegion.updateBrkRegion(81910), 81920);
}

TEST(MemRegionTest, UpdateBrkRegionOnAddrGreaterThanHeapSize) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);
  EXPECT_EXIT(
      { memRegion.updateBrkRegion(81925); }, ::testing::ExitedWithCode(1),
      "Attemped to allocate more memory than is available to the process.");
}

TEST(MemRegionTest, MmapRegionNoStartAddr) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);
}

TEST(MemRegionTest, MultipleMmapRegionNoStartAddr) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);

  retAddr = memRegion.mmapRegion(0, 4000, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 4096);

  ASSERT_EQ(memRegion.getVMASize(), 2);

  retAddr = memRegion.mmapRegion(0, 8192, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + (4096 * 2));

  retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + (4096 * 4));

  ASSERT_EQ(memRegion.getVMASize(), 4);
}

TEST(MemRegionTest, MmapRegionStartAddr) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);

  retAddr = memRegion.mmapRegion(mmapStart + 8192, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 8192);
}

TEST(MemRegionTest, MmapRegionUnalignedStartAddr) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);

  retAddr = memRegion.mmapRegion(mmapStart + 8100, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 8192);
}

TEST(MemRegionTest, MmapRegionAllocatesBetweenVmas) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);

  retAddr = memRegion.mmapRegion(mmapStart + 12288, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 12288);

  retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 4096);

  retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 8192);

  retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 12288 + 4096);

  ASSERT_EQ(memRegion.getVMASize(), 5);
}

TEST(MemRegionTest, MmapRegionCorrectlyAllocatesOverlappingVmas) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);

  retAddr = memRegion.mmapRegion(mmapStart + 12288, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 12288);

  retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 4096);

  // Address range mmapStart + 4096, mmapStart + 4096 + 4096) has already been
  // mapped. If hint is provided then allocate at a page aligned address equal
  // or greater than hint.
  retAddr = memRegion.mmapRegion(mmapStart + 4096, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart + 8192);
  ASSERT_GE(retAddr, mmapStart + 4096);

  ASSERT_EQ(memRegion.getVMASize(), 4);
}

TEST(MemRegionTest, UnmapRegion) {
  uint64_t heapStart = 0;
  uint64_t heapSize = 81920;
  uint64_t mmapStart = 86016;
  uint64_t mmapSize = 163840;
  uint64_t stackStart = 294912;
  uint64_t stackSize = 40960;
  uint64_t size = stackStart;
  // heapEnd = 81920;
  // mmapEnd = 249856;
  // stackEnd = 253952;

  MemRegion memRegion = MemRegion(stackSize, heapSize, mmapSize, size, 4096,
                                  stackStart, heapStart, mmapStart, stackStart);

  uint64_t retAddr = memRegion.mmapRegion(0, 4096, 0, MAP_PRIVATE, NULL);
  ASSERT_NE(retAddr, 0);
  ASSERT_EQ(retAddr, mmapStart);
}

}  // namespace
