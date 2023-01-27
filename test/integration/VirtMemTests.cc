#include "gtest/gtest.h"
#include "simeng/kernel/MemRegion.hh"
#include "simeng/kernel/Process.hh"
#include "simeng/kernel/SimOS.hh"
#include "simeng/kernel/Vma.hh"
#include "simeng/version.hh"

using namespace simeng::kernel;

namespace {

TEST(VirtMemTest, MmapSysCallNoAddressNoFile) {
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

TEST(VirtMemTest, MmapSysCallNoAddressPageFault) {
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

  uint64_t paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);
  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  uint64_t paddrWOffset = simOS.getProcess()->translate(mmapStart + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, MmapSysCallOnAddressAndPageFault) {
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
  uint64_t mmapStart = simOS.getProcess()->getMemRegion().getMmapStart();

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart + 4096, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess()->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess()->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vm_start, mmapStart + 4096);
  ASSERT_EQ(vma->vm_end, mmapStart + 8192);
  ASSERT_EQ(vma->size, 4096);
  ASSERT_EQ(vma->hasFile(), false);

  uint64_t paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);
  simOS.handleVAddrTranslation(mmapStart + 4096, 0);
  paddr = simOS.getProcess()->translate(mmapStart + 4096);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  uint64_t paddrWOffset = simOS.getProcess()->translate(mmapStart + 4096 + 20);
  ASSERT_EQ(paddrWOffset, paddr + 20);
}

TEST(VirtMemTest, UnmapSyscall) {
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
  uint64_t mmapStart = simOS.getProcess()->getMemRegion().getMmapStart();

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess()->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess()->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vm_start, mmapStart);
  ASSERT_EQ(vma->vm_end, mmapStart + 4096);
  ASSERT_EQ(vma->size, 4096);
  ASSERT_EQ(vma->hasFile(), false);

  uint64_t paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  simOS.handleVAddrTranslation(mmapStart, 0);
  paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_NE(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  retVal = simOS.getSyscallHandler()->munmap(mmapStart, 4096);
  ASSERT_EQ(retVal, 4096);

  paddr = simOS.getProcess()->translate(mmapStart);
  ASSERT_EQ(paddr, masks::faults::pagetable::fault |
                       masks::faults::pagetable::translate);

  ASSERT_EQ(simOS.getProcess()->getMemRegion().getVMASize(), 0);

  vma = simOS.getProcess()->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma == NULL);
}

TEST(VirtMemTest, MmapSyscallWithFileNoOffset) {
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

  std::string build_dir_path(SIMENG_BUILD_DIR);
  std::string fpath = build_dir_path + "/test/unit/data/Data.txt";
  HostBackedFileMMaps* hfmap = new HostBackedFileMMaps();

  int fd = open(fpath.c_str(), O_RDWR);
  ASSERT_NE(fd, -1);

  HostFileMMap* fmap = hfmap->mapfd(fd, 4096, 0);

  // Create the instance of the OS
  simeng::kernel::SimOS simOS = simeng::kernel::SimOS(1, nullptr, memory);
  uint64_t mmapStart = simOS.getProcess()->getMemRegion().getMmapStart();

  uint64_t retVal =
      simOS.getSyscallHandler()->mmap(mmapStart, 4096, 0, 0, -1, 0);
  ASSERT_NE(retVal, 0);
  ASSERT_EQ(simOS.getProcess()->getMemRegion().getVMASize(), 1);

  VMA* vma = simOS.getProcess()->getMemRegion().getVMAHead();
  EXPECT_TRUE(vma != NULL);

  ASSERT_EQ(vma->vm_start, mmapStart);
  ASSERT_EQ(vma->vm_end, mmapStart + 4096);
  ASSERT_EQ(vma->size, 4096);

  ASSERT_NE(close(fd), -1);
}
}  // namespace
