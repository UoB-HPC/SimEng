#include "gtest/gtest.h"
#include "simeng/kernel/MemRegion.hh"
#include "simeng/kernel/Process.hh"
#include "simeng/kernel/SimOS.hh"
#include "simeng/kernel/Vma.hh"

using namespace simeng::kernel;

namespace {
TEST(VirtMemTest, MmapSysCall) {
  Config::set(
      "{Core: {Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, "
      "Vector-Length: 512, Streaming-Vector-Length: 512}, Process-Image: "
      "{Heap-Size: 100000, Stack-Size: 100000}, CPU-Info: "
      "{Generate-Special-Dir: "
      "False}}");
  // Create global memory
  std::shared_ptr<simeng::memory::Mem> memory =
      std::make_shared<simeng::memory::SimpleMem>(300000);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS = simeng::kernel::SimOS(1, nullptr, memory);

  uint64_t retVal = simOS.getSyscallHandler()->mmap(0, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess()->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess()->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  uint64_t mmapStart = simOS.getProcess()->getMemRegion().getMmapStart();
  ASSERT_EQ(vma->vm_start, mmapStart);
  ASSERT_EQ(vma->vm_end, mmapStart + 4096);
  ASSERT_EQ(vma->size, 4096);
  ASSERT_EQ(vma->hasFile(), false);
}

}  // namespace
